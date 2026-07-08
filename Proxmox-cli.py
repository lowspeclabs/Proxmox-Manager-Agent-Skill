#!/usr/bin/env python3
"""
Proxmox Agent Harness CLI.

A small, agent-friendly interface for inspecting and safely managing a
Proxmox VE lab through the Proxmox REST API.  It reads connection settings
from a `.env` file in the repository root, logs every action under
`scripts/logs/`, and defaults to read-only / dry-run behavior.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
import argparse
import datetime
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"
DEFAULT_LOG_DIR = REPO_ROOT / "scripts" / "logs"

EXIT_SUCCESS = 0
EXIT_VALIDATION = 1
EXIT_CONFIG = 2
EXIT_AUTH = 3
EXIT_API = 4
EXIT_TIMEOUT = 5
EXIT_NOOP = 6
EXIT_SAFETY = 10
EXIT_INTERNAL = 99

REDACTED = "***REDACTED***"
SENSITIVE_KEYS_RE = re.compile(r"(?i)(secret|token|password|key)")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class Config:
    """Holds validated Proxmox connection configuration."""

    def __init__(self, raw: dict[str, str]):
        self.raw = raw
        # Support both spec format (PROXMOX_API_URL) and prompt.md format (PROXMOX_HOST + PROXMOX_PORT).
        api_url = (raw.get("PROXMOX_API_URL") or "").strip().rstrip("/")
        host = (raw.get("PROXMOX_HOST") or "").strip()
        port = _parse_int(raw.get("PROXMOX_PORT", "8006"), 8006)
        if api_url:
            self.api_url = api_url
        elif host:
            self.api_url = f"https://{host}:{port}/api2/json"
        else:
            self.api_url = ""
        # Support both spec format (full token id) and prompt.md format (user + token id).
        token_id = (raw.get("PROXMOX_API_TOKEN_ID") or "").strip()
        api_user = (raw.get("PROXMOX_API_USER") or "").strip()
        if token_id and "!" in token_id:
            self.token_id = token_id
        elif token_id and api_user:
            self.token_id = f"{api_user}!{token_id}"
        else:
            self.token_id = token_id
        self.token_secret = (raw.get("PROXMOX_API_TOKEN_SECRET") or "").strip()
        self.verify_ssl = _parse_bool(raw.get("PROXMOX_VERIFY_SSL", "true"))
        self.timeout_seconds = _parse_int(raw.get("PROXMOX_TIMEOUT_SECONDS", "30"), 30)
        self.default_node = (raw.get("PROXMOX_DEFAULT_NODE") or "").strip() or None
        self.output_format = (raw.get("PROXMOX_OUTPUT_FORMAT") or "md").strip().lower()
        self.dry_run_default = _parse_bool(raw.get("PROXMOX_DRY_RUN_DEFAULT", "true"))
        self.log_dir = pathlib.Path(raw.get("PROXMOX_LOG_DIR") or DEFAULT_LOG_DIR)

    @property
    def ok(self) -> bool:
        return bool(self.api_url and self.token_id and self.token_secret)

    def missing(self) -> list[str]:
        missing: list[str] = []
        if not self.api_url:
            missing.append("PROXMOX_API_URL")
        if not self.token_id:
            missing.append("PROXMOX_API_TOKEN_ID")
        if not self.token_secret:
            missing.append("PROXMOX_API_TOKEN_SECRET")
        return missing

    def auth_header(self) -> str:
        return f"PVEAPIToken={self.token_id}={self.token_secret}"

    def redacted_header(self) -> str:
        return f"PVEAPIToken={self.token_id}={REDACTED}"


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def load_env(path: pathlib.Path = ENV_PATH) -> dict[str, str]:
    """Parse a simple KEY=VALUE `.env` file, skipping comments and blanks."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------
def redact_value(key: str, value: Any) -> Any:
    """Redact values for keys that look sensitive."""
    if SENSITIVE_KEYS_RE.search(key):
        return REDACTED if value else value
    return value


def redact_data(data: Any) -> Any:
    """Recursively redact sensitive-looking keys from dict/list structures."""
    if isinstance(data, dict):
        return {k: REDACTED if SENSITIVE_KEYS_RE.search(k) else redact_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [redact_data(v) for v in data]
    return data


def redact_string(text: str, config: Config) -> str:
    """Redact the token secret and Authorization header fragments in a string."""
    if not text:
        return text
    secret = config.token_secret
    if secret:
        text = text.replace(secret, REDACTED)
    text = text.replace(config.auth_header(), config.redacted_header())
    text = re.sub(r"(?i)Authorization:\s*PVEAPIToken=[^\s\"']+=[^\s\"']+", f"Authorization: {config.redacted_header()}", text)
    return text


SENSITIVE_ARGV_FLAGS = {
    "--password",
    "--token-secret",
    "--api-token-secret",
    "--secret",
    "--key",
    "--private-key",
}


def _redact_argv(argv: list[str], config: Config | None = None) -> list[str]:
    """Redact values that follow sensitive CLI flags, and apply string redaction."""
    redacted: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            redacted.append(REDACTED)
            skip_next = False
            continue
        if arg.lower() in SENSITIVE_ARGV_FLAGS:
            redacted.append(arg)
            skip_next = True
            continue
        redacted.append(arg)
    if config is not None:
        return [redact_string(str(a), config) for a in redacted]
    return redacted


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class Logger:
    """JSONL logger for CLI actions."""

    def __init__(self, log_dir: pathlib.Path, no_log: bool = False, config: Config | None = None):
        self.no_log = no_log
        self.log_dir = log_dir
        self.config = config
        self.entries: list[dict[str, Any]] = []
        self.file_path: pathlib.Path | None = None
        if not no_log:
            log_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            self.file_path = log_dir / f"proxmox-cli-{stamp}.jsonl"
            try:
                self.file_path.touch(exist_ok=True)
            except OSError:
                pass

    def log(
        self,
        event: str,
        argv: list[str],
        method: str | None = None,
        endpoint: str | None = None,
        status_code: int | None = None,
        duration_ms: int | None = None,
        ok: bool = True,
        dry_run: bool = False,
        response_summary: str | None = None,
        error: str | None = None,
        task_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now().astimezone().isoformat(),
            "event": event,
            "argv": argv,
            "dry_run": dry_run,
            "ok": ok,
        }
        if method is not None:
            entry["method"] = method
        if endpoint is not None:
            entry["endpoint"] = endpoint
        if status_code is not None:
            entry["status_code"] = status_code
        if duration_ms is not None:
            entry["duration_ms"] = duration_ms
        if response_summary is not None:
            entry["response_summary"] = response_summary
        if error is not None:
            entry["error"] = error
        if task_id is not None:
            entry["task_id"] = task_id
        if extra:
            entry.update(extra)
        self.entries.append(entry)
        self._flush_entry(entry)

    def _flush_entry(self, entry: dict[str, Any]) -> None:
        if self.no_log or self.file_path is None:
            return
        try:
            flush_entry = dict(entry)
            if self.config is not None:
                flush_entry["argv"] = _redact_argv(flush_entry.get("argv", []), self.config)
                for key, value in flush_entry.items():
                    if isinstance(value, str):
                        flush_entry[key] = redact_string(value, self.config)
            with self.file_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(flush_entry, default=str) + "\n")
        except OSError:
            pass

    def latest_path(self) -> pathlib.Path:
        return self.log_dir / "latest.jsonl"

    def symlink_latest(self) -> None:
        if self.no_log or self.file_path is None:
            return
        latest = self.latest_path()
        try:
            if latest.exists() or latest.is_symlink():
                latest.unlink()
            latest.symlink_to(self.file_path.name)
        except OSError:
            pass


def latest_log_file(log_dir: pathlib.Path) -> pathlib.Path | None:
    """Return the most recently created log file, or None."""
    if not log_dir.exists():
        return None
    files = [p for p in log_dir.iterdir() if p.is_file() and p.name.startswith("proxmox-cli-")]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
class ProxmoxClient:
    """Small reusable Proxmox REST API client."""

    def __init__(self, config: Config, logger: Logger, verbose: bool = False):
        self.config = config
        self.logger = logger
        self.verbose = verbose
        self.ssl_context = ssl.create_default_context()
        if not config.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self.config.api_url + endpoint
        headers = {
            "Authorization": self.config.auth_header(),
            "Accept": "application/json",
        }
        body: bytes | None = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        start = time.time()
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                status = resp.getcode()
                duration_ms = int((time.time() - start) * 1000)
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    payload = {"_raw": raw}
                return {
                    "ok": True,
                    "status_code": status,
                    "method": method,
                    "endpoint": endpoint,
                    "data": payload.get("data", payload),
                    "error": None,
                    "duration_ms": duration_ms,
                }
        except urllib.error.HTTPError as exc:
            duration_ms = int((time.time() - start) * 1000)
            raw = exc.read().decode("utf-8", errors="replace") if exc.readable() else ""
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {"_raw": raw}
            msg = payload.get("errors", raw) or str(exc)
            return {
                "ok": False,
                "status_code": exc.code,
                "method": method,
                "endpoint": endpoint,
                "data": payload.get("data", payload),
                "error": msg,
                "duration_ms": duration_ms,
            }
        except urllib.error.URLError as exc:
            duration_ms = int((time.time() - start) * 1000)
            reason = str(exc.reason)
            return {
                "ok": False,
                "status_code": None,
                "method": method,
                "endpoint": endpoint,
                "data": None,
                "error": reason,
                "duration_ms": duration_ms,
            }
        except TimeoutError:
            duration_ms = int((time.time() - start) * 1000)
            return {
                "ok": False,
                "status_code": None,
                "method": method,
                "endpoint": endpoint,
                "data": None,
                "error": "Request timed out",
                "duration_ms": duration_ms,
            }

    def get(self, endpoint: str) -> dict[str, Any]:
        return self._request("GET", endpoint)

    def post(self, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("POST", endpoint, data)

    def put(self, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("PUT", endpoint, data)

    def delete(self, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("DELETE", endpoint, data)


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
def render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, default=str)


def render_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "(no data)"
    widths = {c: len(c) for c in columns}
    for row in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))
    lines: list[str] = []
    lines.append("  ".join(c.upper().ljust(widths[c]) for c in columns))
    for row in rows:
        lines.append("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in columns))
    return "\n".join(lines)


def render_markdown(title: str, items: list[tuple[str, Any]]) -> str:
    lines = [f"## {title}", ""]
    for label, value in items:
        if value is None:
            value = ""
        lines.append(f"- {label}: {value}")
    return "\n".join(lines)


def render_error_markdown(error_type: str, message: str, hint: str, log_path: pathlib.Path | None) -> str:
    lines = ["## Error", "", f"- Type: {error_type}", f"- Message: {message}"]
    if hint:
        lines.append(f"- Hint: {hint}")
    if log_path:
        lines.append(f"- Log: {log_path}")
    return "\n".join(lines)


def render_output(result: dict[str, Any], fmt: str, title: str = "Result") -> str:
    ok = result.get("ok", False)
    data = result.get("data")
    error = result.get("error")

    if fmt == "json":
        return render_json(result)

    if not ok:
        return render_error_markdown(
            error_type=result.get("error_type", "api_error"),
            message=str(error or "Unknown error"),
            hint=result.get("hint", ""),
            log_path=result.get("log_path"),
        )

    if fmt == "table":
        if isinstance(data, list) and data:
            return render_table(data, list(data[0].keys()))
        return json.dumps(data, indent=2, default=str)

    # markdown
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = [(str(i), json.dumps(v, default=str)) for i, v in enumerate(data)]
    else:
        items = [("Result", data)]
    return render_markdown(title, items)


# ---------------------------------------------------------------------------
# Safety guards
# ---------------------------------------------------------------------------
def require_execute(args: argparse.Namespace, action: str) -> dict[str, Any] | None:
    """Return a dry-run result if --execute is not present."""
    if getattr(args, "execute", False):
        return None
    return {
        "ok": True,
        "dry_run": True,
        "would_call": action,
        "message": "Dry run only. Re-run with --execute to apply.",
    }


def require_destructive(args: argparse.Namespace, confirm_id: str) -> dict[str, Any] | None:
    """Return a safety-blocked result if destructive guards are missing."""
    if not getattr(args, "execute", False):
        return {
            "ok": True,
            "dry_run": True,
            "would_call": f"destructive action on {confirm_id}",
            "message": "Dry run only. Re-run with --execute to apply.",
        }
    if not getattr(args, "force", False):
        return {
            "ok": False,
            "error_type": "safety_guard",
            "error": "Destructive action requires --force.",
            "hint": "Add --force if you really intend to destroy this resource.",
        }
    if getattr(args, "confirm", None) != confirm_id:
        return {
            "ok": False,
            "error_type": "safety_guard",
            "error": f"Destructive action requires --confirm {confirm_id}.",
            "hint": "Pass the exact resource ID to confirm the operation.",
        }
    return None


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    data: dict[str, Any] = {
        ".env_found": ENV_PATH.exists(),
        "api_url": config.api_url or REDACTED,
        "token_id": config.token_id or REDACTED,
        "token_secret": REDACTED if config.token_secret else "missing",
        "ssl_verification": "enabled" if config.verify_ssl else "disabled (WARNING)",
        "log_directory": str(config.log_dir),
    }
    if not config.ok:
        data["config_status"] = "missing required values: " + ", ".join(config.missing())
        result = {"ok": False, "error_type": "config", "data": data, "error": data["config_status"]}
        print(render_output(result, args.format, title="Doctor"))
        return EXIT_CONFIG

    start = time.time()
    resp = client.get("/version")
    duration_ms = int((time.time() - start) * 1000)
    data["api_connectivity"] = "ok" if resp["ok"] else "failed"
    version_data = resp.get("data") or {}
    summary = f"version={version_data.get('version', 'unknown')}"
    if not resp["ok"]:
        data["error"] = str(resp.get("error", "unknown"))
    logger.log(
        event="doctor",
        argv=sys.argv[1:],
        method="GET",
        endpoint="/version",
        status_code=resp.get("status_code"),
        duration_ms=duration_ms,
        ok=resp["ok"],
        response_summary=summary,
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": data, "error": resp.get("error")}
    print(render_output(result, args.format, title="Doctor"))
    return _exit_code_for(resp)


def cmd_health(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    endpoints = ["/version", "/cluster/status", "/nodes"]
    results: dict[str, Any] = {}
    ok = True
    for endpoint in endpoints:
        resp = client.get(endpoint)
        logger.log(
            event="api_call",
            argv=sys.argv[1:],
            method="GET",
            endpoint=endpoint,
            status_code=resp.get("status_code"),
            duration_ms=resp.get("duration_ms"),
            ok=resp["ok"],
            response_summary=f"data_keys={list((resp.get('data') or {}).keys()) if isinstance(resp.get('data'), dict) else 'list'}",
            error=resp.get("error"),
        )
        results[endpoint] = resp
        if not resp["ok"]:
            ok = False

    data: dict[str, Any] = {}
    if results.get("/version", {}).get("ok"):
        data["version"] = results["/version"]["data"]
    if results.get("/cluster/status", {}).get("ok"):
        data["cluster"] = results["/cluster/status"]["data"]
    if results.get("/nodes", {}).get("ok"):
        data["nodes"] = results["/nodes"]["data"]

    result = {"ok": ok, "data": data, "error": None if ok else "One or more health checks failed"}
    print(render_output(result, args.format, title="Health"))
    if ok:
        return EXIT_SUCCESS
    failed = next((r for r in results.values() if not r.get("ok")), None)
    return _exit_code_for(failed) if failed else EXIT_API


def cmd_nodes_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    resp = client.get("/nodes")
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint="/nodes",
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"nodes={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    data = resp.get("data", []) if resp["ok"] else None
    result = {"ok": resp["ok"], "data": data, "error": resp.get("error")}
    print(render_output(result, args.format, title="Nodes"))
    return _exit_code_for(resp)


def cmd_node_status(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/status"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Node {node} Status"))
    return _exit_code_for(resp)


def cmd_vms_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/qemu"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vms={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"VMs on {node}"))
    return _exit_code_for(resp)


def cmd_next_id(
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
    title: str = "Next Free ID",
) -> int:
    endpoint = "/cluster/nextid"
    if getattr(args, "vmid", None) is not None:
        endpoint = f"/cluster/nextid?vmid={args.vmid}"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"next_id={resp.get('data')}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": {"next_id": resp.get("data")}, "error": resp.get("error")}
    print(render_output(result, args.format, title=title))
    return _exit_code_for(resp)


def cmd_vm_status(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/qemu/{args.vmid}/status/current"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"VM {args.vmid} Status"))
    return _exit_code_for(resp)


def cmd_vm_config(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/qemu/{args.vmid}/config"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"VM {args.vmid} Config"))
    return _exit_code_for(resp)


def _vm_state_change(
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
    action: str,
    destructive: bool = False,
) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/qemu/{vmid}/status/{action}"

    if destructive:
        guard = require_destructive(args, vmid)
    else:
        guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    resp = client.post(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action={action} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"VM {vmid} {action.title()}"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_vm_start(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_state_change(args, config, client, logger, "start")


def cmd_vm_shutdown(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_state_change(args, config, client, logger, "shutdown")


def cmd_vm_stop(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_state_change(args, config, client, logger, "stop", destructive=True)


def cmd_vm_reboot(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_state_change(args, config, client, logger, "reboot")


def cmd_vm_create(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/qemu"

    guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    body: dict[str, Any] = {
        "vmid": vmid,
        "name": args.name,
    }
    if getattr(args, "storage", None):
        body["storage"] = args.storage
    if getattr(args, "memory", None) is not None:
        body["memory"] = args.memory
    if getattr(args, "cores", None) is not None:
        body["cores"] = args.cores
    if getattr(args, "sockets", None) is not None:
        body["sockets"] = args.sockets
    if getattr(args, "cpu", None):
        body["cpu"] = args.cpu
    if getattr(args, "ostype", None):
        body["ostype"] = args.ostype
    if getattr(args, "net0", None):
        body["net0"] = args.net0
    if getattr(args, "scsihw", None):
        body["scsihw"] = args.scsihw
    if getattr(args, "data", None):
        try:
            extra = json.loads(args.data)
            body.update(extra)
        except json.JSONDecodeError:
            print(render_error_markdown("validation", "--data must be valid JSON", "", logger.file_path))
            return EXIT_VALIDATION

    resp = client.post(endpoint, body)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action=create task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"VM {vmid} Create"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_vm_delete(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/qemu/{vmid}"

    guard = require_destructive(args, vmid)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="DELETE",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    resp = client.delete(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="DELETE",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action=delete task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"VM {vmid} Delete"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_vm_snapshot_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/qemu/{args.vmid}/snapshot"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"VM {args.vmid} Snapshots"))
    return _exit_code_for(resp)


def _vm_snapshot_change(
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
    action: str,
    destructive: bool = False,
) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    name = args.name
    if action == "create":
        endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot"
    else:
        endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot/{name}"

    if destructive:
        guard = require_destructive(args, vmid)
    else:
        guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST" if action == "create" else "DELETE",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    if action == "create":
        body: dict[str, Any] | None = {"snapname": name}
        resp = client.post(endpoint, body)
    else:
        resp = client.delete(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST" if action == "create" else "DELETE",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} snapshot={name} action={action} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"VM {vmid} Snapshot {action.title()}"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_vm_snapshot_create(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_snapshot_change(args, config, client, logger, "create")


def cmd_vm_snapshot_delete(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _vm_snapshot_change(args, config, client, logger, "delete", destructive=True)


def cmd_lxcs_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/lxc"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} lxcs={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"LXCs on {node}"))
    return _exit_code_for(resp)


def cmd_lxc_status(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/lxc/{args.vmid}/status/current"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"LXC {args.vmid} Status"))
    return _exit_code_for(resp)


def cmd_lxc_config(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/lxc/{args.vmid}/config"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"LXC {args.vmid} Config"))
    return _exit_code_for(resp)


def _lxc_state_change(
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
    action: str,
    destructive: bool = False,
) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/lxc/{vmid}/status/{action}"

    if destructive:
        guard = require_destructive(args, vmid)
    else:
        guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    resp = client.post(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action={action} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"LXC {vmid} {action.title()}"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_lxc_start(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _lxc_state_change(args, config, client, logger, "start")


def cmd_lxc_shutdown(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _lxc_state_change(args, config, client, logger, "shutdown")


def cmd_lxc_stop(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _lxc_state_change(args, config, client, logger, "stop", destructive=True)


def _is_debian_13_template(ostemplate: str | None) -> bool:
    if not ostemplate:
        return False
    return "debian-13" in ostemplate.lower()


def _lxc_console_fix_instructions(vmid: str | int) -> str:
    return f"""\
Note: Debian 13 LXC containers may show a blank Proxmox web console because
systemd 257's console-getty.service and container-getty@.service include
ImportCredential directives that fail inside LXC (status=243/CREDENTIALS).
No login prompt appears on /dev/console or /dev/tty1.

To fix VMID {vmid}, run these commands on the Proxmox node:

  pct exec {vmid} -- mkdir -p /etc/systemd/system/console-getty.service.d
  pct exec {vmid} -- sh -c 'printf "[Service]\\nImportCredential=\\n" > /etc/systemd/system/console-getty.service.d/override.conf'
  pct exec {vmid} -- mkdir -p /etc/systemd/system/container-getty@.service.d
  pct exec {vmid} -- sh -c 'printf "[Service]\\nImportCredential=\\n" > /etc/systemd/system/container-getty@.service.d/override.conf'
  pct exec {vmid} -- systemctl daemon-reload
  pct exec {vmid} -- systemctl reset-failed console-getty.service container-getty@1.service container-getty@2.service
  pct exec {vmid} -- systemctl start console-getty.service container-getty@1.service container-getty@2.service
"""


def cmd_lxc_create(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/lxc"

    ssh_public_keys = getattr(args, "ssh_public_keys", None)
    ssh_keygen_flag = getattr(args, "ssh_keygen", None)

    guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    if ssh_keygen_flag:
        keygen_path = getattr(args, "ssh_key_path", None) or str(REPO_ROOT / f".lxc-ssh-key-{vmid}")
        keygen_comment = f"lxc-{vmid}-{args.hostname}-opencode"
        keypath = pathlib.Path(keygen_path)
        keypath.parent.mkdir(parents=True, exist_ok=True)
        if keypath.exists():
            print(render_error_markdown("validation", f"SSH key already exists at {keypath}. Remove it or use --ssh-public-keys.", "", logger.file_path))
            return EXIT_VALIDATION
        try:
            result = subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-C", keygen_comment, "-f", str(keypath), "-N", ""],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                print(render_error_markdown("validation", f"ssh-keygen failed: {result.stderr}", "", logger.file_path))
                return EXIT_INTERNAL
        except FileNotFoundError:
            print(render_error_markdown("validation", "ssh-keygen not found on this system", "", logger.file_path))
            return EXIT_INTERNAL
        pubkey_path = keypath.with_suffix(".pub")
        ssh_public_keys = pubkey_path.read_text().strip()

    features_val = getattr(args, "features", None)
    body: dict[str, Any] = {
        "vmid": vmid,
        "hostname": args.hostname,
        "ostemplate": args.ostemplate,
        "storage": args.storage,
    }
    if features_val is not None:
        body["features"] = features_val
    if getattr(args, "password", None):
        body["password"] = args.password
    if getattr(args, "cores", None) is not None:
        body["cores"] = args.cores
    if getattr(args, "memory", None) is not None:
        body["memory"] = args.memory
    if getattr(args, "swap", None) is not None:
        body["swap"] = args.swap
    if getattr(args, "net0", None):
        body["net0"] = args.net0
    if getattr(args, "rootfs", None):
        body["rootfs"] = args.rootfs

    if ssh_public_keys:
        body["ssh-public-keys"] = ssh_public_keys

    if getattr(args, "data", None):
        try:
            extra = json.loads(args.data)
            body.update(extra)
        except json.JSONDecodeError:
            print(render_error_markdown("validation", "--data must be valid JSON", "", logger.file_path))
            return EXIT_VALIDATION

    resp = client.post(endpoint, body)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action=create task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"LXC {vmid} Create"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        exit_code = _wait_for_task(node, task_id, 120, args, config, client, logger)
        if exit_code == EXIT_SUCCESS and _is_debian_13_template(args.ostemplate):
            print()
            print(_lxc_console_fix_instructions(vmid))
        return exit_code
    if resp["ok"] and _is_debian_13_template(args.ostemplate):
        print()
        print(_lxc_console_fix_instructions(vmid))
    return _exit_code_for(resp)


def cmd_lxc_ssh_keygen(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    keyfile = args.keyfile or str(REPO_ROOT / ".lxc-ssh-key")
    vmid_part = args.vmid if getattr(args, "vmid", None) else "default"
    comment = args.comment or f"lxc-{vmid_part}-opencode"
    keypath = pathlib.Path(keyfile)

    if keypath.exists() and not args.force:
        print(render_output({
            "ok": False,
            "data": {"keyfile": str(keypath)},
            "error": f"Key file already exists at {keypath}. Use --force to overwrite."
        }, args.format, title="SSH Key Generation"))
        return EXIT_NOOP

    keypath.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", comment, "-f", str(keypath), "-N", ""],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(render_output({
                "ok": False,
                "data": {"stderr": result.stderr},
                "error": f"ssh-keygen failed (exit {result.returncode})",
            }, args.format, title="SSH Key Generation"))
            return EXIT_INTERNAL

        pubkey_path = keypath.with_suffix(".pub")
        pubkey = pubkey_path.read_text().strip()
        privkey_path = keypath

        print(render_output({
            "ok": True,
            "data": {
                "private_key": str(privkey_path),
                "public_key": str(pubkey_path),
                "public_key_value": pubkey,
                "comment": comment,
            },
        }, args.format, title="SSH Key Generated"))

        logger.log(
            event="ssh_keygen",
            argv=sys.argv[1:],
            extra={
                "private_key": str(privkey_path),
                "public_key": str(pubkey_path),
            },
        )
        return EXIT_SUCCESS
    except FileNotFoundError:
        print(render_output({
            "ok": False,
            "error": "ssh-keygen not found on this system",
        }, args.format, title="SSH Key Generation"))
        return EXIT_INTERNAL


def cmd_lxc_fix_console(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/lxc/{vmid}/config"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=resp.get("error"),
    )
    if not resp["ok"]:
        print(render_output({"ok": False, "data": resp.get("data"), "error": resp.get("error")}, args.format, title=f"LXC {vmid} Config"))
        return _exit_code_for(resp)
    data = resp.get("data") or {}
    ostype = str(data.get("ostype", ""))
    ostemplate = str(data.get("ostemplate", args.ostemplate or ""))
    if ostype == "debian" or _is_debian_13_template(ostemplate):
        print(_lxc_console_fix_instructions(vmid))
    else:
        print(render_markdown(f"LXC {vmid} Console Fix", [("Note", "This template is not known to need the Debian 13 console-getty workaround.")]))
    return EXIT_SUCCESS


def cmd_lxc_delete(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    endpoint = f"/nodes/{node}/lxc/{vmid}"

    guard = require_destructive(args, vmid)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="DELETE",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    resp = client.delete(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="DELETE",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} action=delete task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"LXC {vmid} Delete"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_lxc_snapshot_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/lxc/{args.vmid}/snapshot"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={args.vmid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"LXC {args.vmid} Snapshots"))
    return _exit_code_for(resp)


def _lxc_snapshot_change(
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
    action: str,
    destructive: bool = False,
) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    vmid = str(args.vmid)
    name = args.name
    if action == "create":
        endpoint = f"/nodes/{node}/lxc/{vmid}/snapshot"
    else:
        endpoint = f"/nodes/{node}/lxc/{vmid}/snapshot/{name}"

    if destructive:
        guard = require_destructive(args, vmid)
    else:
        guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST" if action == "create" else "DELETE",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    if action == "create":
        body: dict[str, Any] | None = {"snapname": name}
        resp = client.post(endpoint, body)
    else:
        resp = client.delete(endpoint)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST" if action == "create" else "DELETE",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} snapshot={name} action={action} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"LXC {vmid} Snapshot {action.title()}"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_lxc_snapshot_create(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _lxc_snapshot_change(args, config, client, logger, "create")


def cmd_lxc_snapshot_delete(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    return _lxc_snapshot_change(args, config, client, logger, "delete", destructive=True)


def cmd_storage_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/storage"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} storages={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Storage on {node}"))
    return _exit_code_for(resp)


def cmd_storage_content(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/storage/{args.storage}/content"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} storage={args.storage}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Storage {args.storage} Content"))
    return _exit_code_for(resp)


def cmd_network_list(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/network"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} networks={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Networks on {node}"))
    return _exit_code_for(resp)


def cmd_storage_templates(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/storage/{args.storage}/content?content=vztmpl"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} storage={args.storage}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Templates on {args.storage}"))
    return _exit_code_for(resp)


def cmd_storage_template_download(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/storage/{args.storage}/download-url"

    guard = require_execute(args, endpoint)
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            method="POST",
            endpoint=endpoint,
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    body = {
        "content": "vztmpl",
        "filename": args.filename,
        "url": args.url,
    }
    if getattr(args, "checksum", None):
        body["checksum"] = args.checksum
    if getattr(args, "data", None):
        try:
            extra = json.loads(args.data)
            body.update(extra)
        except json.JSONDecodeError:
            print(render_error_markdown("validation", "--data must be valid JSON", "", logger.file_path))
            return EXIT_VALIDATION

    resp = client.post(endpoint, body)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} storage={args.storage} filename={args.filename} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title="Template Download"))
    if resp["ok"] and task_id and getattr(args, "wait", False):
        return _wait_for_task(node, task_id, 120, args, config, client, logger)
    return _exit_code_for(resp)


def cmd_tasks_recent(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/tasks"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} tasks={len(resp.get('data', [])) if isinstance(resp.get('data'), list) else 'n/a'}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title=f"Recent Tasks on {node}"))
    return _exit_code_for(resp)


def cmd_task_status(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    endpoint = f"/nodes/{node}/tasks/{args.upid}/status"
    resp = client.get(endpoint)
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method="GET",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} upid={args.upid}",
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error")}
    print(render_output(result, args.format, title="Task Status"))
    return _exit_code_for(resp)


def _wait_for_task(
    node: str,
    upid: str,
    timeout: int,
    args: argparse.Namespace,
    config: Config,
    client: ProxmoxClient,
    logger: Logger,
) -> int:
    deadline = time.time() + timeout
    poll_interval = 2
    while time.time() < deadline:
        endpoint = f"/nodes/{node}/tasks/{upid}/status"
        resp = client.get(endpoint)
        logger.log(
            event="task_poll",
            argv=sys.argv[1:],
            method="GET",
            endpoint=endpoint,
            status_code=resp.get("status_code"),
            duration_ms=resp.get("duration_ms"),
            ok=resp["ok"],
            response_summary=f"node={node} upid={upid}",
            error=resp.get("error"),
            task_id=upid,
        )
        if not resp["ok"]:
            print(render_output({"ok": False, "data": None, "error": resp.get("error")}, args.format, title="Task Wait"))
            return _exit_code_for(resp)
        status_data = resp.get("data", {}) or {}
        if status_data.get("status") == "stopped":
            exitstatus = status_data.get("exitstatus", "unknown")
            ok = exitstatus == "OK"
            result = {"ok": ok, "data": status_data, "error": None if ok else f"Task failed: {exitstatus}"}
            print(render_output(result, args.format, title="Task Wait"))
            return _exit_code_for(result)
        time.sleep(poll_interval)
    print(render_output({"ok": False, "data": None, "error": f"Timeout waiting for task {upid}"}, args.format, title="Task Wait"))
    return EXIT_TIMEOUT


def cmd_task_wait(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    node = args.node or config.default_node
    if not node:
        print(render_error_markdown("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path))
        return EXIT_VALIDATION
    upid = args.upid
    timeout = getattr(args, "timeout", 120)
    return _wait_for_task(node, upid, timeout, args, config, client, logger)


def cmd_api_raw(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    method = args.method.lower()
    endpoint = args.endpoint
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    is_write = method in {"post", "put", "delete"}
    if is_write:
        if method == "delete":
            guard = require_destructive(args, endpoint)
        else:
            guard = require_execute(args, endpoint)
        if guard is not None:
            logger.log(
                event="safety_guard",
                argv=sys.argv[1:],
                method=method.upper(),
                endpoint=endpoint,
                ok=guard.get("ok", True),
                dry_run=True,
                response_summary=guard.get("message", "blocked by safety guard"),
            )
            print(render_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run"))
            return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    data: dict[str, Any] | None = None
    if args.data:
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError:
            print(render_error_markdown("validation", "--data must be valid JSON", "", logger.file_path))
            return EXIT_VALIDATION

    if method == "get":
        resp = client.get(endpoint)
    else:
        resp = getattr(client, method)(endpoint, data)
    task_id = _extract_task(resp.get("data"))
    logger.log(
        event="api_call",
        argv=sys.argv[1:],
        method=method.upper(),
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"raw_api method={method} endpoint={endpoint}",
        error=resp.get("error"),
        task_id=task_id,
    )
    result = {"ok": resp["ok"], "data": resp.get("data"), "error": resp.get("error"), "task_id": task_id}
    print(render_output(result, args.format, title=f"API {method.upper()} {endpoint}"))
    return _exit_code_for(resp)


def cmd_logs_latest(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    latest = latest_log_file(config.log_dir)
    if latest is None:
        print(render_error_markdown("not_found", "No log files found", "", None))
        return EXIT_NOOP
    print(str(latest))
    return EXIT_SUCCESS


def cmd_logs_path(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    print(str(config.log_dir))
    return EXIT_SUCCESS


def cmd_logs_tail(args: argparse.Namespace, config: Config, client: ProxmoxClient, logger: Logger) -> int:
    latest = latest_log_file(config.log_dir)
    if latest is None:
        print(render_error_markdown("not_found", "No log files found", "", None))
        return EXIT_NOOP
    lines = getattr(args, "lines", 20)
    try:
        with latest.open("r", encoding="utf-8") as fh:
            all_lines = fh.readlines()
        for line in all_lines[-lines:]:
            print(line.rstrip("\n"))
    except OSError as exc:
        print(render_error_markdown("io_error", str(exc), "", logger.file_path))
        return EXIT_API
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _exit_code_for(resp: dict[str, Any]) -> int:
    """Map an API response to the CLI exit code."""
    if resp.get("ok"):
        return EXIT_SUCCESS
    status = resp.get("status_code")
    if status in {401, 403}:
        return EXIT_AUTH
    if status is None and "timed out" in str(resp.get("error", "")).lower():
        return EXIT_TIMEOUT
    return EXIT_API


def _extract_task(data: Any) -> str | None:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        return data.get("data") or data.get("upid") or data.get("task")
    return None


def _require_config(config: Config, logger: Logger) -> int | None:
    if not config.ok:
        missing = config.missing()
        result = {
            "ok": False,
            "error_type": "config",
            "error": f"Missing required config: {', '.join(missing)}",
            "hint": f"Copy .env.example to .env and set the required values: {', '.join(missing)}",
            "log_path": logger.file_path,
        }
        logger.log(
            event="config_error",
            argv=sys.argv[1:],
            ok=False,
            error=result["error"],
        )
        print(render_output(result, "md"))
        return EXIT_CONFIG
    return None


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _add_common_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--format", choices=["md", "json", "table"], default=None, help="Output format")
    parser.add_argument("--no-log", action="store_true", help="Disable logging")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Force dry-run mode")
    return parser


def _add_timeout_arg(parser: argparse.ArgumentParser, default: int | None = None) -> argparse.ArgumentParser:
    parser.add_argument("--timeout", type=int, default=default, help="Request timeout in seconds")
    return parser


def _add_node_arg(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--node", help="Node name")
    return parser


def _add_vmid_arg(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--vmid", type=int, help="VM/LXC ID")
    return parser


def _add_node_vmid_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    _add_node_arg(parser)
    _add_vmid_arg(parser)
    return parser


def _add_write_guard_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--execute", "--yes", action="store_true", help="Allow state-changing actions")
    parser.add_argument("--wait", action="store_true", help="Wait for task to complete")
    return parser


def _add_destructive_guard_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--execute", "--yes", action="store_true", help="Allow state-changing actions")
    parser.add_argument("--force", action="store_true", help="Confirm destructive intent")
    parser.add_argument("--confirm", help="Confirm resource ID for destructive actions")
    parser.add_argument("--wait", action="store_true", help="Wait for task to complete")
    return parser


def _cmd(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Apply common args to a read-only command subparser."""
    _add_common_args(parser)
    _add_timeout_arg(parser)
    return parser


def _common_parent_parser() -> argparse.ArgumentParser:
    """Return a parent parser with common read-only args for use with argparse parents."""
    parent = argparse.ArgumentParser(add_help=False)
    _add_common_args(parent)
    _add_timeout_arg(parent)
    return parent


def _node_list_parent_parser() -> argparse.ArgumentParser:
    """Return a parent parser with common args plus --node for list-style resources."""
    parent = _common_parent_parser()
    _add_node_arg(parent)
    return parent


def _write_cmd(parser: argparse.ArgumentParser, destructive: bool = False) -> argparse.ArgumentParser:
    """Apply common args and safety guards to a write command subparser."""
    _add_common_args(parser)
    _add_timeout_arg(parser)
    if destructive:
        _add_destructive_guard_args(parser)
    else:
        _add_write_guard_args(parser)
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxmox-cli",
        description="Agent-friendly CLI wrapper for Proxmox VE.",
        epilog="Common options (per-command): --format {md,json,table}, --timeout SECONDS, --no-log, --verbose, --dry-run, --execute, --force, --confirm ID",
    )
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"], default="info")

    sub = parser.add_subparsers(dest="resource", required=True)

    common_parent = _common_parent_parser()
    node_list_parent = _node_list_parent_parser()

    # Meta
    _cmd(sub.add_parser("doctor", help="Check config and API connectivity"))
    _cmd(sub.add_parser("health", help="Show Proxmox health summary"))

    # Nodes
    nodes = sub.add_parser("nodes", help="Node commands", parents=[node_list_parent])
    nodes_sub = nodes.add_subparsers(dest="action", required=False)
    nodes_sub.add_parser("list", help="List nodes", parents=[node_list_parent])

    node = sub.add_parser("node", help="Single node commands")
    node_sub = node.add_subparsers(dest="action", required=True)
    _cmd(_add_node_arg(node_sub.add_parser("status", help="Show node status")))

    # VMs
    vms = sub.add_parser("vms", help="VM list commands", parents=[node_list_parent])
    vms_sub = vms.add_subparsers(dest="action", required=False)
    vms_sub.add_parser("list", help="List VMs", parents=[node_list_parent])
    vms_next_id = _cmd(vms_sub.add_parser("next-id", help="Get next free VM/CT ID"))
    vms_next_id.add_argument("--vmid", type=int, help="Suggested starting ID")

    vm = sub.add_parser("vm", help="Single VM commands")
    vm_sub = vm.add_subparsers(dest="action", required=True)
    _cmd(_add_node_vmid_args(vm_sub.add_parser("status", help="Show VM status")))
    _cmd(_add_node_vmid_args(vm_sub.add_parser("config", help="Show VM config")))
    _write_cmd(_add_node_vmid_args(vm_sub.add_parser("start", help="Start VM (requires --execute)")))
    _write_cmd(_add_node_vmid_args(vm_sub.add_parser("shutdown", help="Shutdown VM (requires --execute)")))
    _write_cmd(_add_node_vmid_args(vm_sub.add_parser("stop", help="Stop VM (requires --execute --force --confirm)")), destructive=True)
    _write_cmd(_add_node_vmid_args(vm_sub.add_parser("reboot", help="Reboot VM (requires --execute)")))
    vm_create = _write_cmd(_add_node_vmid_args(vm_sub.add_parser("create", help="Create VM (requires --execute)")))
    vm_create.add_argument("--name", required=True, help="VM name")
    vm_create.add_argument("--storage", help="Storage pool")
    vm_create.add_argument("--memory", type=int, help="Memory in MB")
    vm_create.add_argument("--cores", type=int, help="Number of cores")
    vm_create.add_argument("--sockets", type=int, help="Number of CPU sockets")
    vm_create.add_argument("--cpu", help="CPU type")
    vm_create.add_argument("--ostype", help="OS type (e.g., l26)")
    vm_create.add_argument("--net0", help="Network interface (e.g., virtio,bridge=vmbr0)")
    vm_create.add_argument("--scsihw", help="SCSI controller type")
    vm_create.add_argument("--data", help="JSON body for extra parameters")
    vm_delete = _write_cmd(_add_node_vmid_args(vm_sub.add_parser("delete", help="Delete VM (requires --execute --force --confirm)")), destructive=True)

    vm_snapshot = vm_sub.add_parser("snapshot", help="VM snapshot commands")
    vm_snapshot_sub = vm_snapshot.add_subparsers(dest="snapshot_action", required=True)
    _cmd(_add_node_vmid_args(vm_snapshot_sub.add_parser("list", help="List VM snapshots")))
    vm_snap_create = _write_cmd(_add_node_vmid_args(vm_snapshot_sub.add_parser("create", help="Create VM snapshot (requires --execute)")))
    vm_snap_create.add_argument("--name", required=True, help="Snapshot name")
    vm_snap_delete = _write_cmd(_add_node_vmid_args(vm_snapshot_sub.add_parser("delete", help="Delete VM snapshot (requires --execute --force --confirm)")), destructive=True)
    vm_snap_delete.add_argument("--name", required=True, help="Snapshot name")

    # LXCs
    lxcs = sub.add_parser("lxcs", help="LXC list commands", parents=[node_list_parent])
    lxcs_sub = lxcs.add_subparsers(dest="action", required=False)
    lxcs_sub.add_parser("list", help="List LXCs", parents=[node_list_parent])
    lxcs_next_id = _cmd(lxcs_sub.add_parser("next-id", help="Get next free VM/CT ID"))
    lxcs_next_id.add_argument("--vmid", type=int, help="Suggested starting ID")

    lxc = sub.add_parser("lxc", help="Single LXC commands")
    lxc_sub = lxc.add_subparsers(dest="action", required=True)
    _cmd(_add_node_vmid_args(lxc_sub.add_parser("status", help="Show LXC status")))
    _cmd(_add_node_vmid_args(lxc_sub.add_parser("config", help="Show LXC config")))
    _write_cmd(_add_node_vmid_args(lxc_sub.add_parser("start", help="Start LXC (requires --execute)")))
    _write_cmd(_add_node_vmid_args(lxc_sub.add_parser("shutdown", help="Shutdown LXC (requires --execute)")))
    _write_cmd(_add_node_vmid_args(lxc_sub.add_parser("stop", help="Stop LXC (requires --execute --force --confirm)")), destructive=True)
    lxc_create = _write_cmd(_add_node_vmid_args(lxc_sub.add_parser("create", help="Create LXC (requires --execute)")))
    lxc_create.add_argument("--hostname", required=True, help="Container hostname")
    lxc_create.add_argument("--ostemplate", required=True, help="OS template")
    lxc_create.add_argument("--storage", required=True, help="Storage pool")
    lxc_create.add_argument("--features", default=None, help="LXC features (e.g., nesting=1). Omit to use default.")
    lxc_create.add_argument("--password", help="Root password")
    lxc_create.add_argument("--cores", type=int, help="Number of cores")
    lxc_create.add_argument("--memory", type=int, help="Memory in MB")
    lxc_create.add_argument("--swap", type=int, help="Swap in MB")
    lxc_create.add_argument("--net0", help="Network interface (e.g., name=eth0,bridge=vmbr0,ip=dhcp)")
    lxc_create.add_argument("--rootfs", help="Root filesystem (e.g., local-lvm:8)")
    lxc_create.add_argument("--ssh-public-keys", help="SSH public key(s) to inject into the container")
    lxc_create.add_argument("--ssh-keygen", action="store_true", help="Generate a new SSH key pair and inject the public key")
    lxc_create.add_argument("--ssh-key-path", help="Path to save generated SSH key (default: ./.lxc-ssh-key-<VMID>)")
    lxc_create.add_argument("--data", help="JSON body for extra parameters")
    lxc_delete = _write_cmd(_add_node_vmid_args(lxc_sub.add_parser("delete", help="Delete LXC (requires --execute --force --confirm)")), destructive=True)
    lxc_fix_console = _cmd(_add_node_vmid_args(lxc_sub.add_parser("fix-console", help="Print Debian 13 LXC console workaround")))
    lxc_fix_console.add_argument("--ostemplate", help="OS template (if not stored in config)")

    lxc_ssh_keygen = _cmd(lxc_sub.add_parser("ssh-keygen", help="Generate an SSH key pair for LXC access"))
    lxc_ssh_keygen.add_argument("--vmid", type=int, help="LXC VMID to include in the key comment")
    lxc_ssh_keygen.add_argument("--keyfile", help="Path to save the key (default: ./.lxc-ssh-key)")
    lxc_ssh_keygen.add_argument("--comment", help="SSH key comment")
    lxc_ssh_keygen.add_argument("--force", action="store_true", help="Overwrite existing key file")

    lxc_snapshot = lxc_sub.add_parser("snapshot", help="LXC snapshot commands")
    lxc_snapshot_sub = lxc_snapshot.add_subparsers(dest="snapshot_action", required=True)
    _cmd(_add_node_vmid_args(lxc_snapshot_sub.add_parser("list", help="List LXC snapshots")))
    lxc_snap_create = _write_cmd(_add_node_vmid_args(lxc_snapshot_sub.add_parser("create", help="Create LXC snapshot (requires --execute)")))
    lxc_snap_create.add_argument("--name", required=True, help="Snapshot name")
    lxc_snap_delete = _write_cmd(_add_node_vmid_args(lxc_snapshot_sub.add_parser("delete", help="Delete LXC snapshot (requires --execute --force --confirm)")), destructive=True)
    lxc_snap_delete.add_argument("--name", required=True, help="Snapshot name")

    # Storage
    storage = sub.add_parser("storage", help="Storage commands")
    storage_sub = storage.add_subparsers(dest="action", required=True)
    _cmd(_add_node_arg(storage_sub.add_parser("list", help="List storage")))
    storage_content = _cmd(_add_node_arg(storage_sub.add_parser("content", help="Show storage content")))
    storage_content.add_argument("--storage", required=True, help="Storage name")
    storage_templates = _cmd(_add_node_arg(storage_sub.add_parser("templates", help="List LXC templates on storage")))
    storage_templates.add_argument("--storage", required=True, help="Storage name")
    storage_download = _write_cmd(_add_node_arg(storage_sub.add_parser("template-download", help="Download LXC template (requires --execute)")))
    storage_download.add_argument("--storage", required=True, help="Storage name")
    storage_download.add_argument("--url", required=True, help="Template URL")
    storage_download.add_argument("--filename", required=True, help="Template filename")
    storage_download.add_argument("--checksum", help="Optional checksum")
    storage_download.add_argument("--data", help="JSON body for extra parameters")

    # Network
    network = sub.add_parser("network", help="Network commands")
    network_sub = network.add_subparsers(dest="action", required=True)
    _cmd(_add_node_arg(network_sub.add_parser("list", help="List networks")))

    # Tasks
    tasks = sub.add_parser("tasks", help="Task commands")
    tasks_sub = tasks.add_subparsers(dest="action", required=True)
    _cmd(_add_node_arg(tasks_sub.add_parser("recent", help="List recent tasks")))

    task = sub.add_parser("task", help="Single task commands")
    task_sub = task.add_subparsers(dest="action", required=True)
    task_status = _cmd(_add_node_arg(task_sub.add_parser("status", help="Show task status")))
    task_status.add_argument("--upid", required=True, help="Task UPID")
    task_wait = _add_common_args(_add_node_arg(task_sub.add_parser("wait", help="Wait for task to complete")))
    task_wait.add_argument("--upid", required=True, help="Task UPID")
    _add_timeout_arg(task_wait, default=120)

    # Logs
    logs = sub.add_parser("logs", help="Log inspection commands")
    logs_sub = logs.add_subparsers(dest="action", required=True)
    _cmd(logs_sub.add_parser("latest", help="Print latest log file path"))
    _cmd(logs_sub.add_parser("path", help="Print log directory path"))
    logs_tail = _cmd(logs_sub.add_parser("tail", help="Tail latest log file"))
    logs_tail.add_argument("--lines", type=int, default=20, help="Number of lines")

    # Raw API
    api = sub.add_parser("api", help="Raw API commands")
    api.add_argument("method", choices=["get", "post", "put", "delete"], help="HTTP method")
    api.add_argument("endpoint", help="API endpoint path")
    _write_cmd(api)
    api.add_argument("--data", help="JSON body for POST/PUT")

    # Prompt.md compatibility aliases
    _cmd(sub.add_parser("status", help="Show Proxmox health summary"))
    sub.add_parser("containers", help="List LXC containers", parents=[node_list_parent])
    _cmd(_add_node_vmid_args(sub.add_parser("vm-status", help="Show VM status")))
    _cmd(_add_node_vmid_args(sub.add_parser("container-status", help="Show LXC container status")))
    _write_cmd(_add_node_vmid_args(sub.add_parser("start-vm", help="Start VM (requires --execute or --yes)")))
    _write_cmd(_add_node_vmid_args(sub.add_parser("reboot-vm", help="Reboot VM (requires --execute or --yes)")))
    _write_cmd(_add_node_vmid_args(sub.add_parser("stop-vm", help="Stop VM (requires --execute or --yes --force --confirm)")), destructive=True)

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_VALIDATION

    env = load_env()
    config = Config(env)

    # Apply CLI overrides
    if getattr(args, "format", None):
        config.output_format = args.format
    if getattr(args, "timeout", None):
        config.timeout_seconds = args.timeout
    if getattr(args, "dry_run", False):
        args.execute = False
        args.force = False

    logger = Logger(config.log_dir, no_log=args.no_log, config=config)
    client = ProxmoxClient(config, logger, verbose=args.verbose)

    try:
        resource = args.resource
        action = getattr(args, "action", None)

        if resource == "doctor":
            return cmd_doctor(args, config, client, logger)

        # Everything except doctor and logs requires valid config.
        if resource != "logs":
            err = _require_config(config, logger)
            if err is not None:
                return err

        if resource == "health" or resource == "status":
            return cmd_health(args, config, client, logger)
        if resource == "nodes" and (action is None or action == "list"):
            return cmd_nodes_list(args, config, client, logger)
        if resource == "node" and action == "status":
            return cmd_node_status(args, config, client, logger)
        if resource == "vms" and (action is None or action == "list"):
            return cmd_vms_list(args, config, client, logger)
        if resource == "vms" and action == "next-id":
            return cmd_next_id(args, config, client, logger, title="Next Free VM/CT ID")
        if resource == "vm" or resource == "vm-status":
            if resource == "vm-status":
                action = "status"
            if action == "status":
                return cmd_vm_status(args, config, client, logger)
            if action == "config":
                return cmd_vm_config(args, config, client, logger)
            if action == "start":
                return cmd_vm_start(args, config, client, logger)
            if action == "shutdown":
                return cmd_vm_shutdown(args, config, client, logger)
            if action == "stop":
                return cmd_vm_stop(args, config, client, logger)
            if action == "reboot":
                return cmd_vm_reboot(args, config, client, logger)
            if action == "create":
                return cmd_vm_create(args, config, client, logger)
            if action == "delete":
                return cmd_vm_delete(args, config, client, logger)
            if action == "snapshot":
                snap_action = getattr(args, "snapshot_action", None)
                if snap_action == "list":
                    return cmd_vm_snapshot_list(args, config, client, logger)
                if snap_action == "create":
                    return cmd_vm_snapshot_create(args, config, client, logger)
                if snap_action == "delete":
                    return cmd_vm_snapshot_delete(args, config, client, logger)
        if resource == "start-vm":
            return cmd_vm_start(args, config, client, logger)
        if resource == "reboot-vm":
            return cmd_vm_reboot(args, config, client, logger)
        if resource == "stop-vm":
            return cmd_vm_stop(args, config, client, logger)
        if resource == "lxcs" and (action is None or action == "list"):
            return cmd_lxcs_list(args, config, client, logger)
        if resource == "lxcs" and action == "next-id":
            return cmd_next_id(args, config, client, logger, title="Next Free VM/CT ID")
        if resource == "containers":
            return cmd_lxcs_list(args, config, client, logger)
        if resource == "container-status":
            return cmd_lxc_status(args, config, client, logger)
        if resource == "lxc":
            if action == "status":
                return cmd_lxc_status(args, config, client, logger)
            if action == "config":
                return cmd_lxc_config(args, config, client, logger)
            if action == "start":
                return cmd_lxc_start(args, config, client, logger)
            if action == "shutdown":
                return cmd_lxc_shutdown(args, config, client, logger)
            if action == "stop":
                return cmd_lxc_stop(args, config, client, logger)
            if action == "create":
                return cmd_lxc_create(args, config, client, logger)
            if action == "delete":
                return cmd_lxc_delete(args, config, client, logger)
            if action == "fix-console":
                return cmd_lxc_fix_console(args, config, client, logger)
            if action == "ssh-keygen":
                return cmd_lxc_ssh_keygen(args, config, client, logger)
            if action == "snapshot":
                snap_action = getattr(args, "snapshot_action", None)
                if snap_action == "list":
                    return cmd_lxc_snapshot_list(args, config, client, logger)
                if snap_action == "create":
                    return cmd_lxc_snapshot_create(args, config, client, logger)
                if snap_action == "delete":
                    return cmd_lxc_snapshot_delete(args, config, client, logger)
        if resource == "storage":
            if action == "list":
                return cmd_storage_list(args, config, client, logger)
            if action == "content":
                return cmd_storage_content(args, config, client, logger)
            if action == "templates":
                return cmd_storage_templates(args, config, client, logger)
            if action == "template-download":
                return cmd_storage_template_download(args, config, client, logger)
        if resource == "network" and action == "list":
            return cmd_network_list(args, config, client, logger)
        if resource == "tasks" and action == "recent":
            return cmd_tasks_recent(args, config, client, logger)
        if resource == "task":
            if action == "status":
                return cmd_task_status(args, config, client, logger)
            if action == "wait":
                return cmd_task_wait(args, config, client, logger)
        if resource == "logs":
            if action == "latest":
                return cmd_logs_latest(args, config, client, logger)
            if action == "path":
                return cmd_logs_path(args, config, client, logger)
            if action == "tail":
                return cmd_logs_tail(args, config, client, logger)
        if resource == "api":
            return cmd_api_raw(args, config, client, logger)

        print(render_error_markdown("unknown_command", f"Unknown command: {resource} {action}", "", logger.file_path))
        return EXIT_VALIDATION
    except Exception as exc:
        msg = str(exc)
        if config.token_secret:
            msg = redact_string(msg, config)
        logger.log(
            event="internal_error",
            argv=sys.argv[1:],
            ok=False,
            error=msg,
        )
        print(render_error_markdown("internal_error", msg, "Check the log for details.", logger.file_path))
        return EXIT_INTERNAL
    finally:
        logger.symlink_latest()


if __name__ == "__main__":
    sys.exit(main())
