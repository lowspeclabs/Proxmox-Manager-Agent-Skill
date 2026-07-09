#!/usr/bin/env python3
"""
Proxmox Console Broker.

A safe, brokered interface for Proxmox VM console access. The agent never
receives raw VNC credentials. All console actions are logged, tiered, and
subject to VM eligibility guards.

Phase 1 implements the read-only broker:
  - doctor
  - status
  - screenshot (best-effort VNC-over-websocket capture, PNG output)
  - read-text (best-effort serial console capture)

Later phases will add send-key, type, run-command, snapshot, and session
management.
"""

import argparse
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse

from PIL import Image

from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_PATH = REPO_ROOT / "scripts" / "Proxmox-cli.py"

_spec = importlib.util.spec_from_file_location("proxmox_cli", str(CLI_PATH))
cli = importlib.util.module_from_spec(_spec)
sys.modules["proxmox_cli"] = cli
_spec.loader.exec_module(cli)

# Reuse helpers from the main CLI
Config = cli.Config
Logger = cli.Logger
ProxmoxClient = cli.ProxmoxClient
emit_output = cli.emit_output
emit_error = cli.emit_error
render_output = cli.render_output
require_execute = cli.require_execute
require_destructive = cli.require_destructive
EXIT_SUCCESS = cli.EXIT_SUCCESS
EXIT_VALIDATION = cli.EXIT_VALIDATION
EXIT_CONFIG = cli.EXIT_CONFIG
EXIT_AUTH = cli.EXIT_AUTH
EXIT_API = cli.EXIT_API
EXIT_TIMEOUT = cli.EXIT_TIMEOUT
EXIT_NOOP = cli.EXIT_NOOP
EXIT_SAFETY = cli.EXIT_SAFETY
EXIT_INTERNAL = cli.EXIT_INTERNAL
REDACTED = cli.REDACTED

DEFAULT_CONSOLE_SESSION_LOG_DIR = REPO_ROOT / "scripts" / "logs" / "console-sessions"

DEFAULT_CONSOLE_KEY_DELAY = 1.5
DEFAULT_CONSOLE_WATCH_INTERVAL = 5.0

SEND_KEY_ALLOWLIST = {
    "Enter", "Tab", "Ctrl+C", "Ctrl+D", "Escape",
    "Up", "Down", "Left", "Right", "Space",
}
SEND_KEY_ALLOWLIST.update(chr(c) for c in range(32, 127) if c not in {9, 10, 13})

TYPE_ALLOWED_CONTROLS = {"\n", "\t", "\r"}

# X11 keysyms used for VNC key events.
X11_KEYSYM = {
    "Enter": 0xFF0D,
    "Tab": 0xFF09,
    "Escape": 0xFF1B,
    "Up": 0xFF52,
    "Down": 0xFF54,
    "Left": 0xFF51,
    "Right": 0xFF53,
    "Space": 0x0020,
    "Control_L": 0xFFE3,
    "Shift_L": 0xFFE1,
    "Alt_L": 0xFFE9,
}

RUN_COMMAND_ALLOWLIST = {
    "ip addr",
    "ip link",
    "ip route",
    "hostname",
    "uname -a",
    "uptime",
    "df -h",
    "free -m",
    "ps aux",
    "ls -la",
    "cat /etc/os-release",
    "systemctl status ssh",
    "systemctl status cron",
    "dmesg",
    "journalctl -xe",
    "ping -c 1 8.8.8.8",
    "ss -tlnp",
    "netstat -tlnp",
    "whoami",
    "id",
    "pwd",
    "lsblk",
}

SHELL_METACHARACTERS_RE = re.compile(r"[&|;`$(){}[\]<>\\#*?~]")


def _send_key_events(vnc: "_VNCClient", events: list[tuple[int, int]]) -> bool:
    """Send a sequence of VNC key events. Each event is (keysym, down_flag)."""
    for keysym, down in events:
        msg = struct.pack("!BBHI", 4, down, 0, keysym)
        if not vnc._send(msg):
            return False
    return True


def _key_name_to_events(key: str) -> list[tuple[int, int]]:
    """Convert a key name from the allowlist to VNC key events."""
    if key == "Ctrl+C":
        return [
            (X11_KEYSYM["Control_L"], 1),
            (0x0063, 1),
            (0x0063, 0),
            (X11_KEYSYM["Control_L"], 0),
        ]
    if key == "Ctrl+D":
        return [
            (X11_KEYSYM["Control_L"], 1),
            (0x0064, 1),
            (0x0064, 0),
            (X11_KEYSYM["Control_L"], 0),
        ]
    if key in X11_KEYSYM:
        keysym = X11_KEYSYM[key]
        return [(keysym, 1), (keysym, 0)]
    if len(key) == 1 and key in SEND_KEY_ALLOWLIST:
        keysym = ord(key)
        return [(keysym, 1), (keysym, 0)]
    return []


def _parse_key_sequence(keys_str: str) -> list[str] | None:
    """
    Parse a comma-separated key sequence.

    Supports repetition syntax: 'Downx10' expands to ten 'Down' keys.
    Returns None if any token is not in the allowlist.
    """
    result: list[str] = []
    for token in keys_str.split(","):
        token = token.strip()
        if not token:
            continue
        # Match KeyxN or Key* N syntax
        match = re.fullmatch(r"(.+?)x(\d+)", token)
        if match:
            key, count = match.group(1), int(match.group(2))
            if key not in SEND_KEY_ALLOWLIST:
                return None
            result.extend([key] * count)
        else:
            if token not in SEND_KEY_ALLOWLIST:
                return None
            result.append(token)
    return result


def _text_to_events(text: str) -> list[tuple[int, int]]:
    """Convert typed text to VNC key events."""
    events: list[tuple[int, int]] = []
    for char in text:
        if char == "\n":
            keysym = X11_KEYSYM["Enter"]
        elif char == "\t":
            keysym = X11_KEYSYM["Tab"]
        elif char == "\r":
            continue
        elif char in TYPE_ALLOWED_CONTROLS or 32 <= ord(char) < 127:
            keysym = ord(char)
        else:
            continue
        events.append((keysym, 1))
        events.append((keysym, 0))
    return events


def _type_text_has_shell_metacharacters(text: str) -> bool:
    return bool(SHELL_METACHARACTERS_RE.search(text))


def _find_recent_snapshot(
    client: ProxmoxClient,
    node: str,
    vmid: str | int,
    name: str | None = None,
    retention_minutes: int = 60,
) -> tuple[str | None, dict[str, Any]]:
    """Return (snapshot_name, api_response) for a matching recent snapshot."""
    endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot"
    resp = client.get(endpoint)
    if not resp["ok"]:
        return None, resp
    snapshots = resp.get("data") or []
    if not isinstance(snapshots, list):
        return None, resp

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    for snap in snapshots:
        if not isinstance(snap, dict):
            continue
        snap_name = str(snap.get("name", ""))
        if name and snap_name == name:
            return snap_name, resp
        if not name and snap_name.startswith("auto-before-console-"):
            snap_time = snap.get("snaptime")
            if snap_time is not None:
                try:
                    snap_dt = datetime.datetime.fromtimestamp(snap_time, tz=datetime.timezone.utc)
                    if (now - snap_dt).total_seconds() <= retention_minutes * 60:
                        return snap_name, resp
                except (TypeError, OSError, ValueError):
                    pass
            else:
                return snap_name, resp
    return None, resp


def _wait_for_task(
    node: str,
    upid: str,
    timeout: int,
    client: ProxmoxClient,
) -> dict[str, Any]:
    deadline = time.time() + timeout
    poll_interval = 2
    while time.time() < deadline:
        endpoint = f"/nodes/{node}/tasks/{upid}/status"
        resp = client.get(endpoint)
        if not resp["ok"]:
            return resp
        status_data = resp.get("data", {}) or {}
        if status_data.get("status") == "stopped":
            exitstatus = status_data.get("exitstatus", "unknown")
            ok = exitstatus == "OK"
            return {"ok": ok, "data": status_data, "error": None if ok else f"Task failed: {exitstatus}"}
        time.sleep(poll_interval)
    return {"ok": False, "data": None, "error": f"Timeout waiting for task {upid}"}


class ConsoleConfig(Config):
    def __init__(self, raw: dict[str, str]):
        super().__init__(raw)
        self.console_allowed_vmids = self._parse_vmids(raw.get("PROXMOX_CONSOLE_ALLOWED_VMIDS", ""))
        self.console_tier = self._parse_tier(raw.get("PROXMOX_CONSOLE_TIER", "1"))
        self.console_require_snapshot = self._parse_bool(raw.get("PROXMOX_CONSOLE_REQUIRE_SNAPSHOT", "true"))
        self.console_key_delay = self._parse_float(raw.get("PROXMOX_CONSOLE_KEY_DELAY"), DEFAULT_CONSOLE_KEY_DELAY)
        self.console_watch_interval = self._parse_float(raw.get("PROXMOX_CONSOLE_WATCH_INTERVAL"), DEFAULT_CONSOLE_WATCH_INTERVAL)
        default_session_dir = self.log_dir / "console-sessions"
        self.console_session_log_dir = pathlib.Path(raw.get("PROXMOX_CONSOLE_SESSION_LOG_DIR") or default_session_dir)
        try:
            self.console_session_log_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _parse_vmids(self, value: str | None) -> list[int]:
        if not value:
            return []
        return [int(x.strip()) for x in value.split(",") if x.strip().isdigit()]

    def _parse_tier(self, value: str | None) -> int:
        if value is None:
            return 1
        try:
            tier = int(value.strip())
            return max(1, min(4, tier))
        except ValueError:
            return 1

    def _parse_float(self, value: str | None, default: float) -> float:
        if value is None:
            return default
        try:
            return max(0.0, float(value.strip()))
        except ValueError:
            return default

    def _parse_bool(self, value: str | None) -> bool:
        if value is None:
            return False
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def is_console_allowed(self, vmid: int | str) -> bool:
        if not self.console_allowed_vmids:
            return False
        try:
            return int(vmid) in self.console_allowed_vmids
        except ValueError:
            return False


def _effective_delay(args: argparse.Namespace, config: ConsoleConfig) -> float:
    """Return the key delay from --delay flag, env var, or default."""
    delay = getattr(args, "delay", None)
    if delay is not None:
        return max(0.0, float(delay))
    return config.console_key_delay


def _console_error_result(error_type: str, message: str, hint: str = "") -> dict[str, Any]:
    return {"ok": False, "error_type": error_type, "error": message, "hint": hint}


def _session_files(config: ConsoleConfig, vmid: str | int) -> list[pathlib.Path]:
    if not config.console_session_log_dir.exists():
        return []
    pattern = re.compile(rf"^\d{{8}}-\d{{6}}-{vmid}\.")
    return [p for p in config.console_session_log_dir.iterdir() if p.is_file() and pattern.match(p.name)]


def _check_eligibility(
    args: argparse.Namespace,
    config: ConsoleConfig,
    logger: Logger,
    required_tier: int,
) -> dict[str, Any] | None:
    vmid = getattr(args, "vmid", None)
    if vmid is None:
        return _console_error_result("validation", "--vmid is required")
    if not config.is_console_allowed(vmid):
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"vmid={vmid} not in PROXMOX_CONSOLE_ALLOWED_VMIDS",
        )
        return _console_error_result(
            "safety_guard",
            f"VMID {vmid} is not allowed for console access.",
            "Add it to PROXMOX_CONSOLE_ALLOWED_VMIDS in .env.",
        )
    if config.console_tier < required_tier:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"tier {required_tier} required, configured tier {config.console_tier}",
        )
        return _console_error_result(
            "safety_guard",
            f"Console tier {required_tier} required, but PROXMOX_CONSOLE_TIER is set to {config.console_tier}.",
            f"Raise PROXMOX_CONSOLE_TIER to at least {required_tier} to use this command.",
        )
    return None


def _require_node(args: argparse.Namespace, config: ConsoleConfig, logger: Logger) -> str | None:
    node = args.node or config.default_node
    if not node:
        emit_error("validation", "--node is required", "Set PROXMOX_DEFAULT_NODE or pass --node.", logger.file_path)
        return None
    return node


def _log_console_event(
    logger: Logger,
    event: str,
    args: argparse.Namespace,
    ok: bool,
    extra: dict[str, Any] | None = None,
    snapshot: str | None = None,
    session_id: str | None = None,
) -> None:
    entry_extra: dict[str, Any] = {"node": getattr(args, "node", None), "vmid": getattr(args, "vmid", None)}
    if snapshot:
        entry_extra["snapshot"] = snapshot
    if session_id:
        entry_extra["session_id"] = session_id
    if extra:
        entry_extra.update(extra)
    logger.log(
        event=event,
        argv=sys.argv[1:],
        ok=ok,
        extra=entry_extra,
    )


def _parse_api_url_parts(config: ConsoleConfig) -> tuple[str, int, bool]:
    url = config.api_url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    return host, port, use_ssl


def _generate_websocket_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def _websocket_accept_key(key: str) -> str:
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode("ascii")).digest()).decode("ascii")


class _WebSocketFrame:
    __slots__ = ("opcode", "payload")

    def __init__(self, opcode: int, payload: bytes):
        self.opcode = opcode
        self.payload = payload


class _WebSocketClient:
    def __init__(self, host: str, port: int, use_ssl: bool, ssl_context: ssl.SSLContext, timeout: int):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self, path: str, headers: dict[str, str] | None = None) -> bool:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                sock = self.ssl_context.wrap_socket(sock, server_hostname=self.host)
            self.sock = sock

            key = _generate_websocket_key()
            all_headers = {
                "Host": f"{self.host}:{self.port}",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13",
            }
            if headers:
                all_headers.update(headers)

            request_lines = [f"GET {path} HTTP/1.1"]
            for k, v in all_headers.items():
                request_lines.append(f"{k}: {v}")
            request_lines.append("\r\n")
            sock.sendall("\r\n".join(request_lines).encode("ascii"))

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    return False
                response += chunk
            header, _ = response.split(b"\r\n\r\n", 1)
            status_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            if not status_line.startswith("HTTP/1.1 101") and not status_line.startswith("HTTP/1.0 101"):
                return False
            return True
        except Exception:
            return False

    def send_binary(self, data: bytes) -> bool:
        if self.sock is None:
            return False
        try:
            self.sock.sendall(self._encode_frame(0x2, data))
            return True
        except Exception:
            return False

    def recv(self) -> _WebSocketFrame | None:
        if self.sock is None:
            return None
        try:
            self.sock.settimeout(self.timeout)
            header = self._recv_bytes(2)
            if not header:
                return None
            b1, b2 = header
            opcode = b1 & 0x0F
            masked = (b2 >> 7) & 1
            length = b2 & 0x7F
            if length == 126:
                length_bytes = self._recv_bytes(2)
                if not length_bytes:
                    return None
                length = struct.unpack("!H", length_bytes)[0]
            elif length == 127:
                length_bytes = self._recv_bytes(8)
                if not length_bytes:
                    return None
                length = struct.unpack("!Q", length_bytes)[0]

            if masked:
                mask = self._recv_bytes(4)
                if not mask:
                    return None
                payload = self._recv_bytes(length)
                if payload is None:
                    return None
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            else:
                payload = self._recv_bytes(length)
                if payload is None:
                    return None
            return _WebSocketFrame(opcode, payload)
        except Exception:
            return None

    def _recv_bytes(self, n: int) -> bytes | None:
        if self.sock is None:
            return None
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _encode_frame(self, opcode: int, data: bytes) -> bytes:
        header = bytes([0x80 | opcode])
        length = len(data)
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += bytes([0x80 | 126]) + struct.pack("!H", length)
        else:
            header += bytes([0x80 | 127]) + struct.pack("!Q", length)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return header + mask + masked

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ---------------------------------------------------------------------------
# DES implementation for VNC authentication
# ---------------------------------------------------------------------------
# Pure-Python DES-ECB used only for VNC "VNC authentication" (security type 2).
# The password is truncated/padded to 8 bytes and each byte is bit-reversed
# before being used as the DES key, per the VNC spec.

_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

_DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

_DES_E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

_DES_P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

_DES_PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

_DES_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_DES_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _permute_bits(bits: str, table: list[int]) -> str:
    return "".join(bits[i - 1] for i in table)


def _shift_left_bits(bits: str, n: int) -> str:
    return bits[n:] + bits[:n]


def _xor_bits(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _sbox_lookup(bits: str, sbox: list[int]) -> str:
    row = int(bits[0] + bits[5], 2)
    col = int(bits[1:5], 2)
    return format(sbox[row * 16 + col], "04b")


def _f_function(right: str, subkey: str) -> str:
    expanded = _permute_bits(right, _DES_E)
    xored = _xor_bits(expanded, subkey)
    sbox_out = "".join(_sbox_lookup(xored[i * 6 : (i + 1) * 6], _DES_SBOX[i]) for i in range(8))
    return _permute_bits(sbox_out, _DES_P)


def _des_key_schedule(key_bits: str) -> list[str]:
    key56 = _permute_bits(key_bits, _DES_PC1)
    left = key56[:28]
    right = key56[28:]
    subkeys = []
    for shift in _DES_SHIFT:
        left = _shift_left_bits(left, shift)
        right = _shift_left_bits(right, shift)
        subkeys.append(_permute_bits(left + right, _DES_PC2))
    return subkeys


def _des_encrypt_block(block: bytes, key_bits: str) -> bytes:
    bits = _permute_bits(_bytes_to_bits(block), _DES_IP)
    left = bits[:32]
    right = bits[32:]
    subkeys = _des_key_schedule(key_bits)
    for i in range(16):
        left, right = right, _xor_bits(left, _f_function(right, subkeys[i]))
    bits = right + left
    return _bits_to_bytes(_permute_bits(bits, _DES_FP))


def _reverse_byte_bits(b: int) -> int:
    result = 0
    for i in range(8):
        if b & (1 << i):
            result |= 1 << (7 - i)
    return result


def _vnc_des_key(password: str) -> str:
    key_bytes = password.encode("utf-8")[:8].ljust(8, b"\x00")
    reversed_bytes = bytes(_reverse_byte_bits(b) for b in key_bytes)
    return _bytes_to_bits(reversed_bytes)


def _vnc_auth_response(password: str, challenge: bytes) -> bytes:
    key_bits = _vnc_des_key(password)
    response = b""
    for i in range(0, len(challenge), 8):
        response += _des_encrypt_block(challenge[i : i + 8], key_bits)
    return response


class _VNCClient:
    def __init__(self, ws_client: _WebSocketClient):
        self.ws = ws_client
        self.width = 0
        self.height = 0
        self.pixel_format: dict[str, Any] = {}
        self._buffer = b""

    def _recv(self, n: int) -> bytes | None:
        while len(self._buffer) < n:
            frame = self.ws.recv()
            if frame is None:
                return None
            if frame.opcode == 0x8:
                return None
            self._buffer += frame.payload
        data = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return data

    def _recv_line(self) -> bytes | None:
        while b"\n" not in self._buffer:
            frame = self.ws.recv()
            if frame is None:
                return None
            if frame.opcode == 0x8:
                return None
            self._buffer += frame.payload
        line, self._buffer = self._buffer.split(b"\n", 1)
        return line + b"\n"

    def _send(self, data: bytes) -> bool:
        return self.ws.send_binary(data)

    def connect(self, password: str | None = None) -> bool:
        version = self._recv_line()
        if not version or not version.startswith(b"RFB "):
            return False
        if not self._send(b"RFB 003.008\n"):
            return False

        sec_count = self._recv(1)
        if sec_count is None:
            return False
        count = sec_count[0]
        if count == 0:
            return False
        sec_types = self._recv(count)
        if sec_types is None:
            return False

        if 1 in sec_types:
            if not self._send(bytes([1])):
                return False
        elif 2 in sec_types and password:
            if not self._send(bytes([2])):
                return False
            challenge = self._recv(16)
            if challenge is None or len(challenge) != 16:
                return False
            response = _vnc_auth_response(password, challenge)
            if not self._send(response):
                return False
        else:
            return False

        result = self._recv(4)
        if result is None or struct.unpack("!I", result)[0] != 0:
            return False

        if not self._send(bytes([0])):
            return False

        server_init = self._recv(24)
        if server_init is None or len(server_init) < 24:
            return False
        self.width = struct.unpack("!H", server_init[0:2])[0]
        self.height = struct.unpack("!H", server_init[2:4])[0]
        fmt = server_init[4:20]
        self.pixel_format = {
            "bpp": fmt[0],
            "depth": fmt[1],
            "big_endian": fmt[2] != 0,
            "true_color": fmt[3] != 0,
            "red_max": struct.unpack("!H", fmt[4:6])[0],
            "green_max": struct.unpack("!H", fmt[6:8])[0],
            "blue_max": struct.unpack("!H", fmt[8:10])[0],
            "red_shift": fmt[10],
            "green_shift": fmt[11],
            "blue_shift": fmt[12],
        }
        name_len = struct.unpack("!I", server_init[20:24])[0]
        if name_len > 0:
            name = self._recv(name_len)
            if name is None:
                return False
        return True

    def _read_framebuffer_update(self) -> tuple[bytes, int, int, int] | None:
        """Read one raw framebuffer update; return (raw, w, h, bpp) or None."""
        header = self._recv(4)
        if header is None or len(header) < 4 or header[0] != 0:
            return None
        num_rects = struct.unpack("!H", header[2:4])[0]
        if num_rects != 1:
            return None

        rect_header = self._recv(12)
        if rect_header is None or len(rect_header) < 12:
            return None
        w = struct.unpack("!H", rect_header[4:6])[0]
        h = struct.unpack("!H", rect_header[6:8])[0]
        encoding = struct.unpack("!i", rect_header[8:12])[0]
        if encoding != 0:
            return None

        bpp = self.pixel_format.get("bpp", 32)
        if bpp == 32:
            pixel_bytes = 4
        elif bpp == 16:
            pixel_bytes = 2
        else:
            return None
        total = w * h * pixel_bytes
        raw = self._recv(total)
        if raw is None or len(raw) < total:
            return None
        return raw, w, h, bpp

    def request_screenshot(self, stable: bool = True) -> bytes | None:
        if not self.width or not self.height:
            return None
        req = struct.pack("!BBHHHH", 3, 0, 0, 0, self.width, self.height)
        if not self._send(req):
            return None

        result = self._read_framebuffer_update()
        if result is None:
            return None
        raw, w, h, bpp = result
        if not stable:
            return self._to_png(raw, w, h, bpp)

        # For slow or transitional console states, wait until the framebuffer
        # stops changing before returning a screenshot. This avoids capturing
        # partial animation or mid-transition frames.
        stable_cycles = 0
        for _ in range(10):
            time.sleep(0.5)
            if not self._send(req):
                return None
            next_result = self._read_framebuffer_update()
            if next_result is None:
                return None
            raw2, w2, h2, bpp2 = next_result
            if raw2 == raw and w2 == w and h2 == h and bpp2 == bpp:
                stable_cycles += 1
                if stable_cycles >= 2:
                    break
            else:
                raw, w, h, bpp = raw2, w2, h2, bpp2
                stable_cycles = 0
        return self._to_png(raw, w, h, bpp)

    def _to_png(self, raw: bytes, w: int, h: int, bpp: int) -> bytes | None:
        if bpp not in (16, 32):
            return None
        red_shift = self.pixel_format.get("red_shift", 16)
        green_shift = self.pixel_format.get("green_shift", 8)
        blue_shift = self.pixel_format.get("blue_shift", 0)
        red_max = self.pixel_format.get("red_max", 255)
        green_max = self.pixel_format.get("green_max", 255)
        blue_max = self.pixel_format.get("blue_max", 255)
        big_endian = self.pixel_format.get("big_endian", False)
        fmt = ">" if big_endian else "<"
        if bpp == 32:
            unpack_fmt = f"{fmt}I"
            stride = 4
        elif bpp == 16:
            unpack_fmt = f"{fmt}H"
            stride = 2
        else:
            return None

        pixels = bytearray()
        for row in range(h):
            row_start = row * w * stride
            for col in range(w):
                idx = row_start + col * stride
                pixel = struct.unpack(unpack_fmt, raw[idx:idx + stride])[0]
                r = (pixel >> red_shift) & red_max
                g = (pixel >> green_shift) & green_max
                b = (pixel >> blue_shift) & blue_max
                if red_max != 255:
                    r = (r * 255) // red_max
                if green_max != 255:
                    g = (g * 255) // green_max
                if blue_max != 255:
                    b = (b * 255) // blue_max
                pixels.extend([r, g, b])
        img = Image.frombytes("RGB", (w, h), bytes(pixels))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()


class _SerialClient:
    def __init__(self, ws_client: _WebSocketClient):
        self.ws = ws_client

    def read_available(self, timeout: float = 2.0) -> bytes:
        text = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = self.ws.recv()
            if frame is None:
                break
            if frame.opcode == 0x8:
                break
            text += frame.payload
        return text


@contextlib.contextmanager
def _vnc_session(
    config: ConsoleConfig,
    node: str,
    vmid: str,
    ticket: str,
    port: str | int,
    timeout: int,
    password: str | None = None,
):
    """Context manager that yields a connected _VNCClient, closing on exit."""
    host, api_port, use_ssl = _parse_api_url_parts(config)
    ssl_context = ssl.create_default_context()
    if not config.verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    quoted_ticket = urllib.parse.quote(ticket, safe="")
    path = f"/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={quoted_ticket}"
    headers = {"Authorization": config.auth_header()}

    ws = _WebSocketClient(host, api_port, use_ssl, ssl_context, timeout)
    vnc: _VNCClient | None = None
    try:
        if not ws.connect(path, headers):
            raise ConnectionError("Failed to establish VNC websocket connection")
        vnc = _VNCClient(ws)
        if not vnc.connect(password=password or ticket):
            raise ConnectionError("Failed to complete VNC handshake")
        yield vnc
    finally:
        ws.close()


def _capture_vnc_screenshot(
    config: ConsoleConfig,
    node: str,
    vmid: str,
    ticket: str,
    port: str | int,
    output_path: pathlib.Path,
    timeout: int,
    password: str | None = None,
) -> bool:
    try:
        with _vnc_session(config, node, vmid, ticket, port, timeout, password=password) as vnc:
            png = vnc.request_screenshot(stable=True)
            if png is None:
                return False
            _write_screenshot(png, output_path, vmid)
            return True
    except Exception:
        return False


def _write_screenshot(png: bytes, screenshot_path: pathlib.Path, vmid: str | int) -> None:
    """Write a PNG screenshot to the session log dir and a /tmp review copy."""
    screenshot_path.write_bytes(png)
    try:
        review_path = pathlib.Path(f"/tmp/console-{vmid}-{screenshot_path.name}")
        review_path.write_bytes(png)
    except OSError:
        pass


def _capture_serial_text(
    config: ConsoleConfig,
    node: str,
    vmid: str,
    ticket: str,
    port: str | int,
    timeout: int,
) -> bytes:
    host, api_port, use_ssl = _parse_api_url_parts(config)
    ssl_context = ssl.create_default_context()
    if not config.verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    quoted_ticket = urllib.parse.quote(ticket, safe="")
    path = f"/api2/json/nodes/{node}/qemu/{vmid}/termwebsocket?port={port}&termproxy={quoted_ticket}"
    headers = {"Authorization": config.auth_header()}

    ws = _WebSocketClient(host, api_port, use_ssl, ssl_context, timeout)
    try:
        if not ws.connect(path, headers):
            return b""
        serial = _SerialClient(ws)
        return serial.read_available(timeout=min(timeout, 5.0))
    finally:
        ws.close()


def _save_session_event(config: ConsoleConfig, event: dict[str, Any]) -> None:
    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = session_dir / f"{stamp}-{event.get('vmid', 'unknown')}.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except OSError:
        pass


def _new_session_id() -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    rand = os.urandom(4).hex()
    return f"sess-{stamp}-{rand}"


def cmd_doctor(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    data: dict[str, Any] = {
        ".env_found": cli.ENV_PATH.exists(),
        "api_url": config.api_url or REDACTED,
        "token_id": config.token_id or REDACTED,
        "token_secret": REDACTED if config.token_secret else "missing",
        "ssl_verification": "enabled" if config.verify_ssl else "disabled (WARNING)",
        "log_directory": str(config.log_dir),
        "console_allowed_vmids": config.console_allowed_vmids or "none (all console operations blocked)",
        "console_tier": config.console_tier,
        "console_require_snapshot": config.console_require_snapshot,
        "console_key_delay": config.console_key_delay,
        "console_watch_interval": config.console_watch_interval,
        "console_session_log_dir": str(config.console_session_log_dir),
    }
    if not config.ok:
        data["config_status"] = "missing required values: " + ", ".join(config.missing())
        result = _console_error_result("config", data["config_status"])
        result["data"] = data
        emit_output(result, args.format, title="Console Doctor")
        return EXIT_CONFIG

    if not config.console_allowed_vmids:
        data["console_status"] = "blocked: PROXMOX_CONSOLE_ALLOWED_VMIDS is empty"
        result = _console_error_result("safety", data["console_status"])
        result["data"] = data
        emit_output(result, args.format, title="Console Doctor")
        logger.log(
            event="console_doctor",
            argv=sys.argv[1:],
            ok=False,
            response_summary="console_allowed_vmids empty",
        )
        return EXIT_SAFETY

    resp = client.get("/version")
    data["api_connectivity"] = "ok" if resp["ok"] else "failed"
    version_data = resp.get("data") or {}
    summary = f"version={version_data.get('version', 'unknown')}"
    if not resp["ok"]:
        data["error"] = str(resp.get("error", "unknown"))
    logger.log(
        event="console_doctor",
        argv=sys.argv[1:],
        method="GET",
        endpoint="/version",
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=summary,
        error=resp.get("error"),
    )
    result = {"ok": resp["ok"], "data": data, "error": resp.get("error")}
    emit_output(result, args.format, title="Console Doctor")
    if not resp["ok"]:
        return EXIT_API
    return EXIT_SUCCESS


def cmd_status(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 1)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Status",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    endpoint = f"/nodes/{node}/qemu/{vmid}/status/current"
    resp = client.get(endpoint)
    logger.log(
        event="console_status",
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
        result = {"ok": False, "data": resp.get("data"), "error": resp.get("error")}
        emit_output(result, args.format, title=f"Console Status VM {vmid}")
        return EXIT_API if resp.get("status_code") not in (401, 403) else EXIT_AUTH

    vm_data = resp.get("data") or {}

    snap_endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot"
    snap_resp = client.get(snap_endpoint)
    logger.log(
        event="console_snapshot_list",
        argv=sys.argv[1:],
        method="GET",
        endpoint=snap_endpoint,
        status_code=snap_resp.get("status_code"),
        duration_ms=snap_resp.get("duration_ms"),
        ok=snap_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=snap_resp.get("error"),
    )
    snapshots = snap_resp.get("data") if snap_resp["ok"] else []
    recent_snapshots = []
    if isinstance(snapshots, list):
        recent_snapshots = [
            s for s in snapshots
            if isinstance(s, dict) and str(s.get("name", "")).startswith("auto-before-console-")
        ]

    sessions = _session_files(config, vmid)

    data = {
        "node": node,
        "vmid": vmid,
        "status": vm_data.get("qmpstatus", vm_data.get("status", "unknown")),
        "console_allowed": True,
        "tier": config.console_tier,
        "active_sessions": len(sessions),
        "recent_auto_snapshots": [s.get("name") for s in recent_snapshots[:5]],
        "session_log_dir": str(config.console_session_log_dir),
    }

    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Status VM {vmid}")
    return EXIT_SUCCESS


def _ensure_vm_running(
    args: argparse.Namespace,
    config: ConsoleConfig,
    client: ProxmoxClient,
    logger: Logger,
    vmid: str | int,
) -> dict[str, Any] | None:
    status_endpoint = f"/nodes/{args.node}/qemu/{vmid}/status/current"
    status_resp = client.get(status_endpoint)
    logger.log(
        event="console_status",
        argv=sys.argv[1:],
        method="GET",
        endpoint=status_endpoint,
        status_code=status_resp.get("status_code"),
        duration_ms=status_resp.get("duration_ms"),
        ok=status_resp["ok"],
        response_summary=f"node={args.node} vmid={vmid}",
        error=status_resp.get("error"),
    )
    if not status_resp["ok"]:
        return status_resp
    vm_data = status_resp.get("data") or {}
    if vm_data.get("qmpstatus", vm_data.get("status")) != "running":
        return {"ok": False, "error": f"VM {vmid} is not running", "error_type": "console_error"}
    return None


def cmd_screenshot(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 1)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Screenshot",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    running_check = _ensure_vm_running(args, config, client, logger, vmid)
    if running_check is not None:
        if not running_check.get("ok"):
            result = _console_error_result(
                running_check.get("error_type", "console_error"),
                running_check.get("error", f"VM {vmid} is not running"),
            )
            emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
            return EXIT_API

    vnc_endpoint = f"/nodes/{node}/qemu/{vmid}/vncproxy"
    vnc_resp = client.post(vnc_endpoint, {"websocket": 1})
    logger.log(
        event="console_vncproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=vnc_endpoint,
        status_code=vnc_resp.get("status_code"),
        duration_ms=vnc_resp.get("duration_ms"),
        ok=vnc_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=vnc_resp.get("error"),
    )

    if not vnc_resp["ok"]:
        result = {"ok": False, "data": vnc_resp.get("data"), "error": vnc_resp.get("error")}
        emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
        return EXIT_API

    vnc_data = vnc_resp.get("data") or {}
    ticket = vnc_data.get("ticket")
    password = vnc_data.get("password")
    port = vnc_data.get("port", "5900")

    if not ticket:
        result = _console_error_result("console_error", "No VNC ticket returned by Proxmox")
        emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
        return EXIT_API

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    screenshot_path = session_dir / f"{timestamp}-{vmid}.png"
    session_id = _new_session_id()

    capture_ok = _capture_vnc_screenshot(
        config, node, str(vmid), ticket, port, screenshot_path, config.timeout_seconds, password=password
    )

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_screenshot",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 1,
        "screenshot_path": str(screenshot_path),
        "ok": capture_ok,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_screenshot",
        args,
        ok=capture_ok,
        extra={
            "session_id": session_id,
            "screenshot_path": str(screenshot_path),
            "ticket": REDACTED,
        },
    )

    if capture_ok:
        data = {
            "node": node,
            "vmid": vmid,
            "screenshot_path": str(screenshot_path),
            "format": "png",
            "session_id": session_id,
            "session_log_dir": str(session_dir),
            "ticket": REDACTED,
        }
        result = {"ok": True, "data": data, "error": None}
        emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
        return EXIT_SUCCESS

    ws_url = f"{config.api_url.replace('/api2/json', '')}/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={ticket}"
    redacted_url = ws_url.replace(ticket, REDACTED)
    result = _console_error_result(
        "console_error",
        "Screenshot capture failed.",
        "The VNC ticket was obtained, but the websocket capture could not be completed. "
        "This may be because the VNC server closed the connection or uses an unsupported encoding. "
        "Connect manually with a VNC viewer if needed.",
    )
    result["data"] = {
        "node": node,
        "vmid": vmid,
        "vnc_port": port,
        "websocket_url": redacted_url,
        "session_id": session_id,
    }
    emit_output(result, args.format, title=f"Console Screenshot VM {vmid}")
    return EXIT_API


def cmd_read_text(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 1)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Read-Text",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    running_check = _ensure_vm_running(args, config, client, logger, vmid)
    if running_check is not None:
        if not running_check.get("ok"):
            result = _console_error_result(
                running_check.get("error_type", "console_error"),
                running_check.get("error", f"VM {vmid} is not running"),
            )
            emit_output(result, args.format, title=f"Console Read-Text VM {vmid}")
            return EXIT_API

    config_endpoint = f"/nodes/{node}/qemu/{vmid}/config"
    config_resp = client.get(config_endpoint)
    logger.log(
        event="console_config",
        argv=sys.argv[1:],
        method="GET",
        endpoint=config_endpoint,
        status_code=config_resp.get("status_code"),
        duration_ms=config_resp.get("duration_ms"),
        ok=config_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=config_resp.get("error"),
    )

    has_serial = False
    if config_resp["ok"]:
        vm_config = config_resp.get("data") or {}
        for key in vm_config:
            if key.startswith("serial"):
                has_serial = True
                break

    termproxy_endpoint = f"/nodes/{node}/qemu/{vmid}/termproxy"
    termproxy_resp = client.post(termproxy_endpoint, {})
    logger.log(
        event="console_termproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=termproxy_endpoint,
        status_code=termproxy_resp.get("status_code"),
        duration_ms=termproxy_resp.get("duration_ms"),
        ok=termproxy_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=termproxy_resp.get("error"),
    )

    if not termproxy_resp["ok"]:
        result = _console_error_result(
            "console_error",
            "Could not obtain serial console ticket.",
            "Ensure the VM has a serial device and the API token has VM.Console permission.",
        )
        result["data"] = {"has_serial_device": has_serial}
        emit_output(result, args.format, title=f"Console Read-Text VM {vmid}")
        return EXIT_API

    term_data = termproxy_resp.get("data") or {}
    ticket = term_data.get("ticket")
    port = term_data.get("port", "5900")

    if not ticket:
        result = _console_error_result("console_error", "No serial console ticket returned")
        result["data"] = {"has_serial_device": has_serial}
        emit_output(result, args.format, title=f"Console Read-Text VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Read-Text VM {vmid}")
        return EXIT_API

    session_id = _new_session_id()
    text = _capture_serial_text(config, node, str(vmid), ticket, port, config.timeout_seconds)

    text_path = session_dir / f"{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{vmid}.txt"
    try:
        text_path.write_bytes(text)
    except OSError:
        pass

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_read_text",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 1,
        "text_path": str(text_path),
        "text_length": len(text),
        "ok": True,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_read_text",
        args,
        ok=True,
        extra={
            "session_id": session_id,
            "text_path": str(text_path),
            "text_length": len(text),
            "ticket": REDACTED,
        },
    )

    ws_url = f"{config.api_url.replace('/api2/json', '')}/nodes/{node}/qemu/{vmid}/termwebsocket?port={port}&termproxy={ticket}"
    redacted_url = ws_url.replace(ticket, REDACTED)
    data = {
        "node": node,
        "vmid": vmid,
        "has_serial_device": has_serial,
        "text_length": len(text),
        "text_preview": text[:200].decode("utf-8", errors="replace"),
        "text_path": str(text_path),
        "session_id": session_id,
        "websocket_url": redacted_url,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Read-Text VM {vmid}")
    return EXIT_SUCCESS


def cmd_watch(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 1)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Watch",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    running_check = _ensure_vm_running(args, config, client, logger, vmid)
    if running_check is not None:
        if not running_check.get("ok"):
            result = _console_error_result(
                running_check.get("error_type", "console_error"),
                running_check.get("error", f"VM {vmid} is not running"),
            )
            emit_output(result, args.format, title=f"Console Watch VM {vmid}")
            return EXIT_API

    vnc_endpoint = f"/nodes/{node}/qemu/{vmid}/vncproxy"
    vnc_resp = client.post(vnc_endpoint, {"websocket": 1})
    logger.log(
        event="console_vncproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=vnc_endpoint,
        status_code=vnc_resp.get("status_code"),
        duration_ms=vnc_resp.get("duration_ms"),
        ok=vnc_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=vnc_resp.get("error"),
    )
    if not vnc_resp["ok"]:
        result = {"ok": False, "data": vnc_resp.get("data"), "error": vnc_resp.get("error")}
        emit_output(result, args.format, title=f"Console Watch VM {vmid}")
        return EXIT_API

    vnc_data = vnc_resp.get("data") or {}
    ticket = vnc_data.get("ticket")
    password = vnc_data.get("password")
    port = vnc_data.get("port", "5900")
    if not ticket:
        result = _console_error_result("console_error", "No VNC ticket returned by Proxmox")
        emit_output(result, args.format, title=f"Console Watch VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Watch VM {vmid}")
        return EXIT_API

    session_id = _new_session_id()
    interval = getattr(args, "interval", None)
    if interval is None or interval <= 0:
        interval = config.console_watch_interval
    timeout = getattr(args, "timeout", None)
    if timeout is None or timeout <= 0:
        timeout = config.timeout_seconds
    until_stable = getattr(args, "until_stable", False)
    stable_required = max(1, int(getattr(args, "stable_cycles", 2)))
    save_screenshots = getattr(args, "screenshots", False)

    start = time.time()
    deadline = start + timeout
    previous_png: bytes | None = None
    stable_count = 0
    iterations = 0
    last_screenshot_path: pathlib.Path | None = None
    capture_ok = False
    summary = "watch completed"

    try:
        with _vnc_session(config, node, str(vmid), ticket, port, config.timeout_seconds, password=password) as vnc:
            while time.time() < deadline:
                iterations += 1
                png = vnc.request_screenshot(stable=False)
                if png is None:
                    break

                if save_screenshots:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                    screenshot_path = session_dir / f"{timestamp}-{vmid}.png"
                    _write_screenshot(png, screenshot_path, vmid)
                    last_screenshot_path = screenshot_path

                if until_stable:
                    if previous_png is not None and png == previous_png:
                        stable_count += 1
                        if stable_count >= stable_required:
                            capture_ok = True
                            summary = f"screen stable for {stable_count} consecutive captures"
                            break
                    else:
                        stable_count = 0
                    previous_png = png
                else:
                    capture_ok = True
                    summary = f"captured {iterations} screenshot(s)"
                    break

                time.sleep(interval)
    except Exception as exc:
        logger.log(
            event="console_watch",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"node={node} vmid={vmid} error={exc}",
        )

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_watch",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 1,
        "iterations": iterations,
        "stable": capture_ok and until_stable,
        "screenshot_path": str(last_screenshot_path) if last_screenshot_path else None,
        "ok": capture_ok,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_watch",
        args,
        ok=capture_ok,
        extra={
            "session_id": session_id,
            "iterations": iterations,
            "summary": summary,
            "screenshot_path": str(last_screenshot_path) if last_screenshot_path else None,
            "ticket": REDACTED,
        },
    )

    if not capture_ok:
        result = _console_error_result(
            "console_error",
            "Watch did not reach a stable screen before timeout.",
            "The VM may still be animating, or the VNC session may have closed. Try increasing --timeout or --interval.",
        )
        emit_output(result, args.format, title=f"Console Watch VM {vmid}")
        return EXIT_TIMEOUT

    data = {
        "node": node,
        "vmid": vmid,
        "iterations": iterations,
        "summary": summary,
        "screenshot_path": str(last_screenshot_path) if last_screenshot_path else None,
        "session_id": session_id,
        "ticket": REDACTED,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Watch VM {vmid}")
    return EXIT_SUCCESS


def cmd_send_key(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 2)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Send-Key",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    key = args.key
    if key not in SEND_KEY_ALLOWLIST:
        result = _console_error_result(
            "validation",
            f"Key '{key}' is not in the send-key allowlist.",
            f"Allowed keys: {', '.join(sorted(SEND_KEY_ALLOWLIST))}",
        )
        emit_output(result, args.format, title="Console Send-Key")
        return EXIT_VALIDATION

    guard = require_execute(args, f"send-key to VM {vmid}")
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    running_check = _ensure_vm_running(args, config, client, logger, str(vmid))
    if running_check is not None and not running_check.get("ok"):
        result = _console_error_result(
            running_check.get("error_type", "console_error"),
            running_check.get("error", f"VM {vmid} is not running"),
        )
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    vnc_endpoint = f"/nodes/{node}/qemu/{vmid}/vncproxy"
    vnc_resp = client.post(vnc_endpoint, {"websocket": 1})
    logger.log(
        event="console_vncproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=vnc_endpoint,
        status_code=vnc_resp.get("status_code"),
        duration_ms=vnc_resp.get("duration_ms"),
        ok=vnc_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=vnc_resp.get("error"),
    )
    if not vnc_resp["ok"]:
        result = {"ok": False, "data": vnc_resp.get("data"), "error": vnc_resp.get("error")}
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    vnc_data = vnc_resp.get("data") or {}
    ticket = vnc_data.get("ticket")
    password = vnc_data.get("password")
    port = vnc_data.get("port", "5900")
    if not ticket:
        result = _console_error_result("console_error", "No VNC ticket returned by Proxmox")
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    session_id = _new_session_id()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    screenshot_path = session_dir / f"{timestamp}-{vmid}.png"

    events = _key_name_to_events(key)
    if not events:
        result = _console_error_result("console_error", f"Could not translate key '{key}' to VNC events")
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    try:
        with _vnc_session(config, node, str(vmid), ticket, port, config.timeout_seconds, password=password) as vnc:
            if not _send_key_events(vnc, events):
                raise ConnectionError("Failed to send VNC key events")
            time.sleep(_effective_delay(args, config))
            png = vnc.request_screenshot(stable=True)
            if png is not None:
                _write_screenshot(png, screenshot_path, vmid)
            ok = True
    except Exception as exc:
        ok = False
        logger.log(
            event="console_send_key",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"node={node} vmid={vmid} key={key} error={exc}",
        )

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_send_key",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 2,
        "key": key,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ok": ok,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_send_key",
        args,
        ok=ok,
        extra={
            "session_id": session_id,
            "key": key,
            "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
            "ticket": REDACTED,
        },
    )

    if not ok:
        result = _console_error_result("console_error", "Failed to send key to VM console")
        emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
        return EXIT_API

    data = {
        "node": node,
        "vmid": vmid,
        "key": key,
        "session_id": session_id,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ticket": REDACTED,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Send-Key VM {vmid}")
    return EXIT_SUCCESS


def cmd_send_keys(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 2)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Send-Keys",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    keys = _parse_key_sequence(args.keys)
    if keys is None:
        result = _console_error_result(
            "validation",
            f"Invalid key sequence '{args.keys}'.",
            f"Allowed keys: {', '.join(sorted(SEND_KEY_ALLOWLIST))}. Use comma-separated names; repeat with KeyxN (e.g., Downx10).",
        )
        emit_output(result, args.format, title="Console Send-Keys")
        return EXIT_VALIDATION

    guard = require_execute(args, f"send-keys to VM {vmid}")
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    running_check = _ensure_vm_running(args, config, client, logger, str(vmid))
    if running_check is not None and not running_check.get("ok"):
        result = _console_error_result(
            running_check.get("error_type", "console_error"),
            running_check.get("error", f"VM {vmid} is not running"),
        )
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    vnc_endpoint = f"/nodes/{node}/qemu/{vmid}/vncproxy"
    vnc_resp = client.post(vnc_endpoint, {"websocket": 1})
    logger.log(
        event="console_vncproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=vnc_endpoint,
        status_code=vnc_resp.get("status_code"),
        duration_ms=vnc_resp.get("duration_ms"),
        ok=vnc_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=vnc_resp.get("error"),
    )
    if not vnc_resp["ok"]:
        result = {"ok": False, "data": vnc_resp.get("data"), "error": vnc_resp.get("error")}
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    vnc_data = vnc_resp.get("data") or {}
    ticket = vnc_data.get("ticket")
    password = vnc_data.get("password")
    port = vnc_data.get("port", "5900")
    if not ticket:
        result = _console_error_result("console_error", "No VNC ticket returned by Proxmox")
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    session_id = _new_session_id()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    screenshot_path = session_dir / f"{timestamp}-{vmid}.png"

    events: list[tuple[int, int]] = []
    for key in keys:
        events.extend(_key_name_to_events(key))
    if not events:
        result = _console_error_result("console_error", "Could not translate key sequence to VNC events")
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    try:
        with _vnc_session(config, node, str(vmid), ticket, port, config.timeout_seconds, password=password) as vnc:
            if not _send_key_events(vnc, events):
                raise ConnectionError("Failed to send VNC key events")
            time.sleep(_effective_delay(args, config))
            png = vnc.request_screenshot(stable=True)
            if png is not None:
                _write_screenshot(png, screenshot_path, vmid)
            ok = True
    except Exception as exc:
        ok = False
        logger.log(
            event="console_send_keys",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"node={node} vmid={vmid} keys={args.keys} error={exc}",
        )

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_send_keys",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 2,
        "keys": args.keys,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ok": ok,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_send_keys",
        args,
        ok=ok,
        extra={
            "session_id": session_id,
            "keys": args.keys,
            "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
            "ticket": REDACTED,
        },
    )

    if not ok:
        result = _console_error_result("console_error", "Failed to send keys to VM console")
        emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
        return EXIT_API

    data = {
        "node": node,
        "vmid": vmid,
        "keys": args.keys,
        "session_id": session_id,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ticket": REDACTED,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Send-Keys VM {vmid}")
    return EXIT_SUCCESS


def cmd_run_command(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 2)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Run-Command",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    command = args.command.strip()
    if not command:
        result = _console_error_result("validation", "--command is required")
        emit_output(result, args.format, title="Console Run-Command")
        return EXIT_VALIDATION

    if command not in RUN_COMMAND_ALLOWLIST:
        result = _console_error_result(
            "validation",
            f"Command '{command}' is not in the run-command allowlist.",
            "Contact the administrator to add safe diagnostics to the allowlist.",
        )
        emit_output(result, args.format, title="Console Run-Command")
        return EXIT_VALIDATION

    guard = require_execute(args, f"run-command on VM {vmid}")
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    running_check = _ensure_vm_running(args, config, client, logger, str(vmid))
    if running_check is not None and not running_check.get("ok"):
        result = _console_error_result(
            running_check.get("error_type", "console_error"),
            running_check.get("error", f"VM {vmid} is not running"),
        )
        emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
        return EXIT_API

    cmd_parts = command.split()
    body = {"command": cmd_parts[0], "capture-output": 1}
    if len(cmd_parts) > 1:
        body["arg"] = cmd_parts[1:]

    exec_endpoint = f"/nodes/{node}/qemu/{vmid}/agent/exec"
    exec_resp = client.post(exec_endpoint, body)
    logger.log(
        event="console_agent_exec",
        argv=sys.argv[1:],
        method="POST",
        endpoint=exec_endpoint,
        status_code=exec_resp.get("status_code"),
        duration_ms=exec_resp.get("duration_ms"),
        ok=exec_resp["ok"],
        response_summary=f"node={node} vmid={vmid} command={cmd_parts[0]}",
        error=exec_resp.get("error"),
    )
    if not exec_resp["ok"]:
        result = {"ok": False, "data": exec_resp.get("data"), "error": exec_resp.get("error")}
        emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
        return EXIT_API

    exec_data = exec_resp.get("data") or {}
    pid = exec_data.get("pid")
    if pid is None:
        result = _console_error_result("console_error", "QEMU guest agent did not return a PID")
        emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
        return EXIT_API

    status_endpoint = f"/nodes/{node}/qemu/{vmid}/agent/exec-status"
    deadline = time.time() + min(30, config.timeout_seconds)
    output = {"out-data": "", "err-data": "", "exited": False}
    while time.time() < deadline:
        status_resp = client.post(status_endpoint, {"pid": pid})
        logger.log(
            event="console_agent_exec_status",
            argv=sys.argv[1:],
            method="POST",
            endpoint=status_endpoint,
            status_code=status_resp.get("status_code"),
            duration_ms=status_resp.get("duration_ms"),
            ok=status_resp["ok"],
            response_summary=f"node={node} vmid={vmid} pid={pid}",
            error=status_resp.get("error"),
        )
        if not status_resp["ok"]:
            result = {"ok": False, "data": status_resp.get("data"), "error": status_resp.get("error")}
            emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
            return EXIT_API
        status_data = status_resp.get("data") or {}
        if status_data.get("exited"):
            output = status_data
            break
        time.sleep(1)
    else:
        result = _console_error_result("timeout", f"Timed out waiting for command PID {pid} to exit")
        emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
        return EXIT_TIMEOUT

    session_id = _new_session_id()
    _log_console_event(
        logger,
        "console_run_command",
        args,
        ok=True,
        extra={
            "session_id": session_id,
            "command": command,
            "pid": pid,
            "exit_code": output.get("exitcode"),
        },
    )

    out_data = output.get("out-data", "")
    err_data = output.get("err-data", "")
    if isinstance(out_data, str):
        try:
            out_text = base64.b64decode(out_data).decode("utf-8", errors="replace")
        except Exception:
            out_text = out_data
    else:
        out_text = str(out_data)
    if isinstance(err_data, str):
        try:
            err_text = base64.b64decode(err_data).decode("utf-8", errors="replace")
        except Exception:
            err_text = err_data
    else:
        err_text = str(err_data)

    data = {
        "node": node,
        "vmid": vmid,
        "command": command,
        "pid": pid,
        "exit_code": output.get("exitcode"),
        "stdout": out_text[:2000],
        "stderr": err_text[:2000],
        "session_id": session_id,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Run-Command VM {vmid}")
    return EXIT_SUCCESS


def cmd_type(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 3)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Type",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    guard = require_destructive(args, str(vmid))
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    text = args.text
    if not text:
        result = _console_error_result("validation", "--text is required")
        emit_output(result, args.format, title="Console Type")
        return EXIT_VALIDATION

    if _type_text_has_shell_metacharacters(text) and not getattr(args, "unsafe", False):
        result = _console_error_result(
            "validation",
            "Text contains shell metacharacters. Use --unsafe only if you really intend to.",
            "The --unsafe flag must be explicitly set and the action is logged with a warning.",
        )
        emit_output(result, args.format, title="Console Type")
        return EXIT_VALIDATION

    running_check = _ensure_vm_running(args, config, client, logger, str(vmid))
    if running_check is not None and not running_check.get("ok"):
        result = _console_error_result(
            running_check.get("error_type", "console_error"),
            running_check.get("error", f"VM {vmid} is not running"),
        )
        emit_output(result, args.format, title=f"Console Type VM {vmid}")
        return EXIT_API

    snapshot_name = None
    if config.console_require_snapshot:
        recent_name, _ = _find_recent_snapshot(
            client, node, str(vmid), getattr(args, "snapshot", None), retention_minutes=60
        )
        if recent_name:
            snapshot_name = recent_name
        elif getattr(args, "auto_snapshot", False):
            snapshot_name = f"auto-before-console-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
            snap_endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot"
            snap_resp = client.post(snap_endpoint, {"snapname": snapshot_name})
            logger.log(
                event="console_snapshot_create",
                argv=sys.argv[1:],
                method="POST",
                endpoint=snap_endpoint,
                status_code=snap_resp.get("status_code"),
                duration_ms=snap_resp.get("duration_ms"),
                ok=snap_resp["ok"],
                response_summary=f"node={node} vmid={vmid} snapshot={snapshot_name}",
                error=snap_resp.get("error"),
            )
            if not snap_resp["ok"]:
                result = {"ok": False, "data": snap_resp.get("data"), "error": snap_resp.get("error")}
                emit_output(result, args.format, title=f"Console Type VM {vmid}")
                return EXIT_API
            task_id = cli._extract_task(snap_resp.get("data"))
            if task_id:
                wait_result = _wait_for_task(node, task_id, 120, client)
                if not wait_result.get("ok"):
                    emit_output(wait_result, args.format, title=f"Console Type VM {vmid}")
                    return EXIT_API
        else:
            result = _console_error_result(
                "safety_guard",
                "A recent snapshot is required before typing.",
                "Pass --auto-snapshot to create one, or create one with `snapshot` first.",
            )
            emit_output(result, args.format, title=f"Console Type VM {vmid}")
            return EXIT_SAFETY

    vnc_endpoint = f"/nodes/{node}/qemu/{vmid}/vncproxy"
    vnc_resp = client.post(vnc_endpoint, {"websocket": 1})
    logger.log(
        event="console_vncproxy",
        argv=sys.argv[1:],
        method="POST",
        endpoint=vnc_endpoint,
        status_code=vnc_resp.get("status_code"),
        duration_ms=vnc_resp.get("duration_ms"),
        ok=vnc_resp["ok"],
        response_summary=f"node={node} vmid={vmid}",
        error=vnc_resp.get("error"),
    )
    if not vnc_resp["ok"]:
        result = {"ok": False, "data": vnc_resp.get("data"), "error": vnc_resp.get("error")}
        emit_output(result, args.format, title=f"Console Type VM {vmid}")
        return EXIT_API

    vnc_data = vnc_resp.get("data") or {}
    ticket = vnc_data.get("ticket")
    password = vnc_data.get("password")
    port = vnc_data.get("port", "5900")
    if not ticket:
        result = _console_error_result("console_error", "No VNC ticket returned by Proxmox")
        emit_output(result, args.format, title=f"Console Type VM {vmid}")
        return EXIT_API

    session_dir = config.console_session_log_dir
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result = _console_error_result("io_error", f"Cannot create session log directory: {exc}")
        emit_output(result, args.format, title=f"Console Type VM {vmid}")
        return EXIT_API

    session_id = _new_session_id()
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    screenshot_path = session_dir / f"{timestamp}-{vmid}.png"

    events = _text_to_events(text)
    try:
        with _vnc_session(config, node, str(vmid), ticket, port, config.timeout_seconds, password=password) as vnc:
            if not _send_key_events(vnc, events):
                raise ConnectionError("Failed to send VNC text events")
            time.sleep(_effective_delay(args, config))
            png = vnc.request_screenshot(stable=True)
            if png is not None:
                _write_screenshot(png, screenshot_path, vmid)
            ok = True
    except Exception as exc:
        ok = False
        logger.log(
            event="console_type",
            argv=sys.argv[1:],
            ok=False,
            response_summary=f"node={node} vmid={vmid} input_length={len(text)} error={exc}",
        )

    session_event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "event": "console_type",
        "node": node,
        "vmid": vmid,
        "session_id": session_id,
        "tier": 3,
        "input_length": len(text),
        "snapshot": snapshot_name,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ok": ok,
    }
    _save_session_event(config, session_event)

    _log_console_event(
        logger,
        "console_type",
        args,
        ok=ok,
        extra={
            "session_id": session_id,
            "input_length": len(text),
            "snapshot": snapshot_name,
            "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
            "ticket": REDACTED,
        },
    )

    if not ok:
        result = _console_error_result("console_error", "Failed to type text to VM console")
        emit_output(result, args.format, title=f"Console Type VM {vmid}")
        return EXIT_API

    data = {
        "node": node,
        "vmid": vmid,
        "input_length": len(text),
        "snapshot": snapshot_name,
        "session_id": session_id,
        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
        "ticket": REDACTED,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Type VM {vmid}")
    return EXIT_SUCCESS


def cmd_snapshot(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    eligibility = _check_eligibility(args, config, logger, 2)
    if eligibility is not None:
        emit_output(
            {
                "ok": False,
                "error_type": eligibility["error_type"],
                "error": eligibility["error"],
                "hint": eligibility["hint"],
            },
            args.format,
            title="Console Snapshot",
        )
        return EXIT_SAFETY

    vmid = args.vmid
    name = args.name
    guard = require_execute(args, f"create snapshot on VM {vmid}")
    if guard is not None:
        logger.log(
            event="safety_guard",
            argv=sys.argv[1:],
            ok=guard.get("ok", True),
            dry_run=True,
            response_summary=guard.get("message", "blocked by safety guard"),
        )
        emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
        return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

    endpoint = f"/nodes/{node}/qemu/{vmid}/snapshot"
    resp = client.post(endpoint, {"snapname": name})
    task_id = cli._extract_task(resp.get("data"))
    logger.log(
        event="console_snapshot_create",
        argv=sys.argv[1:],
        method="POST",
        endpoint=endpoint,
        status_code=resp.get("status_code"),
        duration_ms=resp.get("duration_ms"),
        ok=resp["ok"],
        response_summary=f"node={node} vmid={vmid} snapshot={name} task={task_id or 'n/a'}",
        error=resp.get("error"),
        task_id=task_id,
    )
    if not resp["ok"]:
        result = {"ok": False, "data": resp.get("data"), "error": resp.get("error")}
        emit_output(result, args.format, title=f"Console Snapshot VM {vmid}")
        return EXIT_API

    if task_id and getattr(args, "wait", False):
        wait_result = _wait_for_task(node, task_id, getattr(args, "timeout", 120), client)
        if not wait_result.get("ok"):
            emit_output(wait_result, args.format, title=f"Console Snapshot VM {vmid}")
            return EXIT_API

    data = {
        "node": node,
        "vmid": vmid,
        "snapshot": name,
        "task_id": task_id,
    }
    result = {"ok": True, "data": data, "error": None}
    emit_output(result, args.format, title=f"Console Snapshot VM {vmid}")
    return EXIT_SUCCESS


def cmd_session(args: argparse.Namespace, config: ConsoleConfig, client: ProxmoxClient, logger: Logger) -> int:
    node = _require_node(args, config, logger)
    if node is None:
        return EXIT_VALIDATION

    vmid = args.vmid
    session_dir = config.console_session_log_dir

    if getattr(args, "list", False):
        files = sorted(_session_files(config, vmid), key=lambda p: p.name, reverse=True)
        data = {
            "node": node,
            "vmid": vmid,
            "sessions": [
                {
                    "name": p.name,
                    "path": str(p),
                    "size": p.stat().st_size,
                }
                for p in files
            ],
        }
        result = {"ok": True, "data": data, "error": None}
        emit_output(result, args.format, title=f"Console Sessions VM {vmid}")
        return EXIT_SUCCESS

    if getattr(args, "stop", False):
        session_id = args.session_id
        if not session_id:
            result = _console_error_result("validation", "--session-id is required for --stop")
            emit_output(result, args.format, title="Console Session Stop")
            return EXIT_VALIDATION

        guard = require_destructive(args, session_id)
        if guard is not None:
            logger.log(
                event="safety_guard",
                argv=sys.argv[1:],
                ok=guard.get("ok", True),
                dry_run=True,
                response_summary=guard.get("message", "blocked by safety guard"),
            )
            emit_output({"ok": guard.get("ok", True), "data": guard, "error": guard.get("error")}, args.format, title="Dry Run")
            return EXIT_SAFETY if guard.get("ok") is False else EXIT_SUCCESS

        target = session_dir / session_id
        if not target.exists() or not target.is_file():
            result = _console_error_result("not_found", f"Session file not found: {session_id}")
            emit_output(result, args.format, title="Console Session Stop")
            return EXIT_NOOP

        try:
            target.unlink()
        except OSError as exc:
            result = _console_error_result("io_error", f"Failed to delete session file: {exc}")
            emit_output(result, args.format, title="Console Session Stop")
            return EXIT_API

        logger.log(
            event="console_session_stop",
            argv=sys.argv[1:],
            ok=True,
            response_summary=f"node={node} vmid={vmid} session={session_id}",
        )
        data = {"node": node, "vmid": vmid, "session_id": session_id, "stopped": True}
        result = {"ok": True, "data": data, "error": None}
        emit_output(result, args.format, title="Console Session Stop")
        return EXIT_SUCCESS

    result = _console_error_result("validation", "Use --list or --stop for session management")
    emit_output(result, args.format, title="Console Session")
    return EXIT_VALIDATION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxmox-console",
        description="Safe console broker for Proxmox VMs.",
        epilog="Common options: --format {md,json,table}, --no-log, --verbose, --timeout SECONDS",
    )
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"], default="info")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    doctor = sub.add_parser("doctor", help="Check console config and API connectivity")
    doctor.add_argument("--format", choices=["md", "json", "table"], default=None)
    doctor.add_argument("--no-log", action="store_true")
    doctor.add_argument("--verbose", action="store_true")

    for name in ("screenshot", "read-text", "status"):
        cmd = sub.add_parser(name, help=f"Console {name} command")
        cmd.add_argument("--node", help="Node name")
        cmd.add_argument("--vmid", type=int, required=True, help="VM ID")
        cmd.add_argument("--format", choices=["md", "json", "table"], default=None)
        cmd.add_argument("--no-log", action="store_true")
        cmd.add_argument("--verbose", action="store_true")
        cmd.add_argument("--timeout", type=int, help="Request timeout in seconds")

    watch = sub.add_parser("watch", help="Poll the VM console until a condition is met (Tier 1)")
    watch.add_argument("--node", help="Node name")
    watch.add_argument("--vmid", type=int, required=True, help="VM ID")
    watch.add_argument("--until-stable", action="store_true", help="Exit when the screen stops changing")
    watch.add_argument("--stable-cycles", type=int, default=2, help="Consecutive stable frames required (default: 2)")
    watch.add_argument("--interval", type=float, help="Seconds between screenshots (default: env or 5)")
    watch.add_argument("--screenshots", action="store_true", help="Save every screenshot captured during the watch")
    watch.add_argument("--format", choices=["md", "json", "table"], default=None)
    watch.add_argument("--no-log", action="store_true")
    watch.add_argument("--verbose", action="store_true")
    watch.add_argument("--timeout", type=int, help="Maximum seconds to watch")

    send_key = sub.add_parser("send-key", help="Send a single key to the VM console (Tier 2)")
    send_key.add_argument("--node", help="Node name")
    send_key.add_argument("--vmid", type=int, required=True, help="VM ID")
    send_key.add_argument("--key", required=True, help="Key to send")
    send_key.add_argument("--delay", type=float, help="Seconds to wait after the key (default: env or 1.5)")
    send_key.add_argument("--execute", "--yes", action="store_true", help="Allow key input")
    send_key.add_argument("--format", choices=["md", "json", "table"], default=None)
    send_key.add_argument("--no-log", action="store_true")
    send_key.add_argument("--verbose", action="store_true")
    send_key.add_argument("--timeout", type=int, help="Request timeout in seconds")

    send_keys = sub.add_parser("send-keys", help="Send a sequence of keys to the VM console (Tier 2)")
    send_keys.add_argument("--node", help="Node name")
    send_keys.add_argument("--vmid", type=int, required=True, help="VM ID")
    send_keys.add_argument("--keys", required=True, help="Comma-separated key sequence (e.g., 'Space,Downx10,Space,Tab,Enter')")
    send_keys.add_argument("--delay", type=float, help="Seconds to wait after the sequence (default: env or 1.5)")
    send_keys.add_argument("--execute", "--yes", action="store_true", help="Allow key input")
    send_keys.add_argument("--format", choices=["md", "json", "table"], default=None)
    send_keys.add_argument("--no-log", action="store_true")
    send_keys.add_argument("--verbose", action="store_true")
    send_keys.add_argument("--timeout", type=int, help="Request timeout in seconds")

    run_cmd = sub.add_parser("run-command", help="Run a safe diagnostic command via QEMU guest agent (Tier 2)")
    run_cmd.add_argument("--node", help="Node name")
    run_cmd.add_argument("--vmid", type=int, required=True, help="VM ID")
    run_cmd.add_argument("--command", required=True, help="Command to run")
    run_cmd.add_argument("--execute", "--yes", action="store_true", help="Allow command execution")
    run_cmd.add_argument("--format", choices=["md", "json", "table"], default=None)
    run_cmd.add_argument("--no-log", action="store_true")
    run_cmd.add_argument("--verbose", action="store_true")
    run_cmd.add_argument("--timeout", type=int, help="Request timeout in seconds")

    snapshot = sub.add_parser("snapshot", help="Create a snapshot before risky console work (Tier 2)")
    snapshot.add_argument("--node", help="Node name")
    snapshot.add_argument("--vmid", type=int, required=True, help="VM ID")
    snapshot.add_argument("--name", required=True, help="Snapshot name")
    snapshot.add_argument("--execute", "--yes", action="store_true", help="Create the snapshot")
    snapshot.add_argument("--wait", action="store_true", help="Wait for the snapshot task to complete")
    snapshot.add_argument("--format", choices=["md", "json", "table"], default=None)
    snapshot.add_argument("--no-log", action="store_true")
    snapshot.add_argument("--verbose", action="store_true")
    snapshot.add_argument("--timeout", type=int, help="Request timeout in seconds")

    type_cmd = sub.add_parser("type", help="Type text into the VM console (Tier 3)")
    type_cmd.add_argument("--node", help="Node name")
    type_cmd.add_argument("--vmid", type=int, required=True, help="VM ID")
    type_cmd.add_argument("--text", required=True, help="Text to type")
    type_cmd.add_argument("--snapshot", help="Required snapshot name")
    type_cmd.add_argument("--auto-snapshot", action="store_true", help="Create an auto-before-console snapshot if none exists")
    type_cmd.add_argument("--unsafe", action="store_true", help="Allow shell metacharacters in text")
    type_cmd.add_argument("--delay", type=float, help="Seconds to wait after typing (default: env or 1.5)")
    type_cmd.add_argument("--execute", "--yes", action="store_true", help="Allow typing")
    type_cmd.add_argument("--force", action="store_true", help="Confirm destructive intent")
    type_cmd.add_argument("--confirm", help="Confirm resource ID for destructive actions")
    type_cmd.add_argument("--format", choices=["md", "json", "table"], default=None)
    type_cmd.add_argument("--no-log", action="store_true")
    type_cmd.add_argument("--verbose", action="store_true")
    type_cmd.add_argument("--timeout", type=int, help="Request timeout in seconds")

    session = sub.add_parser("session", help="Manage broker session files")
    session.add_argument("--node", help="Node name")
    session.add_argument("--vmid", type=int, required=True, help="VM ID")
    session.add_argument("--list", action="store_true", help="List session files")
    session.add_argument("--stop", action="store_true", help="Stop/delete a session")
    session.add_argument("--session-id", help="Session file name to stop")
    session.add_argument("--execute", "--yes", action="store_true", help="Allow destructive session stop")
    session.add_argument("--force", action="store_true", help="Confirm destructive intent")
    session.add_argument("--confirm", help="Confirm session ID for destructive actions")
    session.add_argument("--format", choices=["md", "json", "table"], default=None)
    session.add_argument("--no-log", action="store_true")
    session.add_argument("--verbose", action="store_true")
    session.add_argument("--timeout", type=int, help="Request timeout in seconds")

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_VALIDATION

    env = cli.load_env()
    config = ConsoleConfig(env)

    if getattr(args, "format", None):
        config.output_format = args.format
    if getattr(args, "timeout", None):
        config.timeout_seconds = args.timeout

    logger = Logger(config.log_dir, no_log=args.no_log, config=config)
    client = ProxmoxClient(config, logger, verbose=args.verbose)

    try:
        subcommand = args.subcommand
        if subcommand == "doctor":
            return cmd_doctor(args, config, client, logger)

        err = cli._require_config(config, logger)
        if err is not None:
            return err

        if subcommand == "status":
            return cmd_status(args, config, client, logger)
        if subcommand == "screenshot":
            return cmd_screenshot(args, config, client, logger)
        if subcommand == "read-text":
            return cmd_read_text(args, config, client, logger)
        if subcommand == "watch":
            return cmd_watch(args, config, client, logger)
        if subcommand == "send-key":
            return cmd_send_key(args, config, client, logger)
        if subcommand == "send-keys":
            return cmd_send_keys(args, config, client, logger)
        if subcommand == "run-command":
            return cmd_run_command(args, config, client, logger)
        if subcommand == "snapshot":
            return cmd_snapshot(args, config, client, logger)
        if subcommand == "type":
            return cmd_type(args, config, client, logger)
        if subcommand == "session":
            return cmd_session(args, config, client, logger)

        emit_error("unknown_command", f"Unknown command: {subcommand}", "", logger.file_path)
        return EXIT_VALIDATION
    except Exception as exc:
        msg = str(exc)
        if config.token_secret:
            msg = cli.redact_string(msg, config)
        logger.log(
            event="internal_error",
            argv=sys.argv[1:],
            ok=False,
            error=msg,
        )
        emit_error("internal_error", msg, "Check the log for details.", logger.file_path)
        return EXIT_INTERNAL
    finally:
        logger.symlink_latest()


if __name__ == "__main__":
    sys.exit(main())
