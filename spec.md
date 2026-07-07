# spec.md — Proxmox Agent Harness CLI

## 1. Project Name

`proxmox-opencode-lab`

## 2. Summary

Build a small, agent-friendly CLI interface that allows an OpenCode-style agent harness to manage a Proxmox VE environment through stable, safe, documented commands.

The CLI will live at:

```text
scripts/Proxmox-cli.py
```

It will read Proxmox API settings from `.env`, use API-token authentication, log every command and result under `scripts/logs/`, and provide markdown-based project memory for bugs and improvements inside the `scripts/` folder.

## 3. Problem Statement

Agents can call shell commands, edit files, and reason through tasks, but direct Proxmox management can be risky because:

- Raw API calls are easy to mistype.
- Proxmox endpoints can be verbose and inconsistent for small local models.
- Destructive actions such as stopping VMs or deleting snapshots must be guarded.
- Agents need durable logs so another agent can understand what happened later.
- Credentials must not be pasted into prompts, logs, or markdown notes.

This project creates a safer adapter between an agent harness and Proxmox.

## 4. Goals

### 4.1 Primary Goals

- Provide a Python CLI that wraps common Proxmox REST API operations.
- Store connection details in `.env` and document required keys in `.env.example`.
- Log all commands, API calls, outcomes, errors, and task IDs.
- Keep logs in `scripts/logs/`.
- Add `AGENTS.md` as the agent operating guide.
- Add `README.md` for project purpose, layout, and design rationale.
- Add `scripts/BUGS.md` and `scripts/IMPROVEMENTS.md` so agents can track issues and future work.
- Favor read-only inspection by default.
- Require explicit confirmation for write and destructive operations.

### 4.2 Secondary Goals

- Make output predictable for small local models.
- Support `json`, `table`, and `md` output formats.
- Add dry-run mode for all state-changing operations.
- Support raw API fallback for advanced users and debugging.
- Provide enough docs for other agents to safely continue the project.

## 5. Non-Goals

This project is not intended to:

- Replace the Proxmox web UI.
- Replace Terraform, Ansible, Pulumi, or full infrastructure-as-code workflows.
- Implement every Proxmox API endpoint in the first version.
- Store secrets in source control.
- Run unguarded bulk destructive operations.
- Automatically discover or mutate production clusters without human review.

## 6. Source Assumptions

The CLI should be designed around these Proxmox behaviors:

- Proxmox VE exposes a REST API under `/api2/json`.
- API tokens can be used for stateless REST access.
- API tokens should be scoped with ACLs and expiration dates when possible.
- API token auth uses an `Authorization` header in this form:

```text
Authorization: PVEAPIToken=USER@REALM!TOKENID=TOKEN_SECRET
```

- `pvesh` exists on Proxmox nodes as a local command-line way to invoke API functions without going through the REST/HTTPS server.

## 7. Recommended Folder Layout

```text
proxmox-opencode-lab/
├─ AGENTS.md
├─ README.md
├─ spec.md
├─ .env.example
├─ scripts/
│  ├─ Proxmox-cli.py
│  ├─ BUGS.md
│  ├─ IMPROVEMENTS.md
│  └─ logs/
│     └─ .gitkeep
└─ docs/
   └─ proxmox-api-notes.md
```

## 8. Layout Rationale

### `AGENTS.md`

Primary operating guide for coding agents. It should tell agents how to install, run, test, log, and safely modify the project.

### `README.md`

Human and agent-facing overview. It should explain what the project does, why it exists, and why the repo is structured this way.

### `spec.md`

Implementation contract. It defines the required behavior, safety model, commands, output formats, tests, and acceptance criteria.

### `.env.example`

Safe template for API connection settings. It must never contain real secrets.

### `scripts/Proxmox-cli.py`

The main CLI entry point. Keeping it under `scripts/` makes it easy for an agent harness to locate and execute.

### `scripts/logs/`

Stores command and result logs close to the CLI script. This keeps operational traces local to the tool that produced them.

### `scripts/BUGS.md`

Agent-maintained bug tracker. Agents must update this file when they hit broken behavior, confusing output, bad docs, or unsafe defaults.

### `scripts/IMPROVEMENTS.md`

Agent-maintained improvement backlog. Agents must update this file when they notice usability, safety, test, or feature improvements.

### `docs/proxmox-api-notes.md`

Reference notes for Proxmox endpoints, auth behavior, task responses, and gotchas discovered during implementation.

## 9. Configuration

The CLI must load config from a `.env` file in the repo root.

### 9.1 Required `.env` Keys

```dotenv
PROXMOX_API_URL=https://proxmox.example.local:8006/api2/json
PROXMOX_API_TOKEN_ID=agent@pve!opencode
PROXMOX_API_TOKEN_SECRET=replace-me
```

### 9.2 Optional `.env` Keys

```dotenv
PROXMOX_VERIFY_SSL=true
PROXMOX_TIMEOUT_SECONDS=30
PROXMOX_DEFAULT_NODE=
PROXMOX_OUTPUT_FORMAT=md
PROXMOX_DRY_RUN_DEFAULT=true
PROXMOX_LOG_DIR=scripts/logs
```

### 9.3 Config Rules

- `.env` must be gitignored.
- `.env.example` must contain placeholders only.
- Token secrets must never appear in logs.
- `doctor` must validate config without exposing secrets.
- SSL verification should default to `true`.
- If users disable SSL verification for a homelab, the CLI must show a warning.

## 10. CLI Design

### 10.1 Command Style

Use a predictable nested command style:

```bash
python scripts/Proxmox-cli.py <resource> <action> [options]
```

Examples:

```bash
python scripts/Proxmox-cli.py health
python scripts/Proxmox-cli.py nodes list
python scripts/Proxmox-cli.py vms list --node pve1
python scripts/Proxmox-cli.py vm status --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101 --execute --wait
```

### 10.2 Global Options

```text
--format md|json|table
--log-level debug|info|warning|error
--no-log
--dry-run
--execute
--timeout <seconds>
--verbose
```

### 10.3 Exit Codes

```text
0   Success
1   CLI validation error
2   Missing or invalid config
3   Authentication or authorization failure
4   Proxmox API error
5   Timeout
6   No-op / already in desired state
10  Safety guard blocked operation
99  Unexpected internal error
```

## 11. Required Commands

### 11.1 Meta Commands

#### `doctor`

Checks config, log folder, basic API connectivity, and SSL behavior.

Example:

```bash
python scripts/Proxmox-cli.py doctor
```

Must report:

- `.env` found or missing.
- API URL present.
- Token ID present.
- Token secret present but redacted.
- SSL verification setting.
- Log directory path.
- API connectivity test result.

#### `health`

Returns basic Proxmox health data.

Recommended calls:

- `GET /version`
- `GET /cluster/status`
- `GET /nodes`

### 11.2 Node Commands

```bash
python scripts/Proxmox-cli.py nodes list
python scripts/Proxmox-cli.py node status --node pve1
```

Recommended endpoints:

```text
GET /nodes
GET /nodes/{node}/status
```

### 11.3 VM Commands

```bash
python scripts/Proxmox-cli.py vms list [--node pve1]
python scripts/Proxmox-cli.py vm status --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm config --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101 --execute
python scripts/Proxmox-cli.py vm shutdown --node pve1 --vmid 101 --execute
python scripts/Proxmox-cli.py vm stop --node pve1 --vmid 101 --execute --force --confirm 101
python scripts/Proxmox-cli.py vm reboot --node pve1 --vmid 101 --execute
```

Recommended endpoints:

```text
GET  /nodes/{node}/qemu
GET  /nodes/{node}/qemu/{vmid}/status/current
GET  /nodes/{node}/qemu/{vmid}/config
POST /nodes/{node}/qemu/{vmid}/status/start
POST /nodes/{node}/qemu/{vmid}/status/shutdown
POST /nodes/{node}/qemu/{vmid}/status/stop
POST /nodes/{node}/qemu/{vmid}/status/reboot
```

### 11.4 VM Snapshot Commands

```bash
python scripts/Proxmox-cli.py vm snapshot list --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm snapshot create --node pve1 --vmid 101 --name before-update --execute
python scripts/Proxmox-cli.py vm snapshot delete --node pve1 --vmid 101 --name before-update --execute --force --confirm 101
```

Recommended endpoints:

```text
GET    /nodes/{node}/qemu/{vmid}/snapshot
POST   /nodes/{node}/qemu/{vmid}/snapshot
DELETE /nodes/{node}/qemu/{vmid}/snapshot/{snapname}
```

### 11.5 LXC Commands

```bash
python scripts/Proxmox-cli.py lxcs list [--node pve1]
python scripts/Proxmox-cli.py lxc status --node pve1 --vmid 201
python scripts/Proxmox-cli.py lxc config --node pve1 --vmid 201
python scripts/Proxmox-cli.py lxc start --node pve1 --vmid 201 --execute
python scripts/Proxmox-cli.py lxc shutdown --node pve1 --vmid 201 --execute
python scripts/Proxmox-cli.py lxc stop --node pve1 --vmid 201 --execute --force --confirm 201
```

Recommended endpoints:

```text
GET  /nodes/{node}/lxc
GET  /nodes/{node}/lxc/{vmid}/status/current
GET  /nodes/{node}/lxc/{vmid}/config
POST /nodes/{node}/lxc/{vmid}/status/start
POST /nodes/{node}/lxc/{vmid}/status/shutdown
POST /nodes/{node}/lxc/{vmid}/status/stop
```

### 11.6 Storage Commands

```bash
python scripts/Proxmox-cli.py storage list --node pve1
python scripts/Proxmox-cli.py storage content --node pve1 --storage local
```

Recommended endpoints:

```text
GET /nodes/{node}/storage
GET /nodes/{node}/storage/{storage}/content
```

### 11.7 Task Commands

```bash
python scripts/Proxmox-cli.py tasks recent --node pve1
python scripts/Proxmox-cli.py task status --node pve1 --upid '<UPID>'
python scripts/Proxmox-cli.py task wait --node pve1 --upid '<UPID>' --timeout 120
```

Recommended endpoints:

```text
GET /nodes/{node}/tasks
GET /nodes/{node}/tasks/{upid}/status
GET /nodes/{node}/tasks/{upid}/log
```

### 11.8 Raw API Commands

Raw API commands are useful for debugging and advanced workflows.

```bash
python scripts/Proxmox-cli.py api get /version
python scripts/Proxmox-cli.py api get /nodes
python scripts/Proxmox-cli.py api post /nodes/pve1/qemu/101/status/start --execute
```

Rules:

- `api get` is allowed by default.
- `api post`, `api put`, and `api delete` require `--execute`.
- `api delete` additionally requires `--force`.
- Raw write operations must print a warning.

### 11.9 Log Commands

```bash
python scripts/Proxmox-cli.py logs latest
python scripts/Proxmox-cli.py logs path
python scripts/Proxmox-cli.py logs tail --lines 50
```

## 12. Safety Model

### 12.1 Default Read-Only Bias

All read commands should work normally.

All state-changing commands must dry-run by default unless `--execute` is present.

### 12.2 Required Write Guard

The following commands require `--execute`:

- VM start/shutdown/stop/reboot.
- LXC start/shutdown/stop.
- Snapshot create/delete.
- Raw API `post`, `put`, and `delete`.

### 12.3 Required Destructive Guard

The following commands require `--execute`, `--force`, and `--confirm <vmid>`:

- VM stop.
- LXC stop.
- Snapshot delete.
- Raw API delete.

### 12.4 No Hidden Bulk Actions

Commands must not perform bulk writes unless the user passes an explicit bulk flag such as `--all`.

If `--all` is ever added, it must also require:

```text
--execute --force --confirm-all
```

### 12.5 Agent-Safe Noninteractive Behavior

The CLI should not rely on interactive prompts for safety. Agents often run commands noninteractively. All safety confirmation must be done through explicit flags.

## 13. Logging Requirements

### 13.1 Log Location

Default log folder:

```text
scripts/logs/
```

The CLI must create this folder if it does not exist.

### 13.2 Log Format

The main log format should be JSONL.

File naming:

```text
scripts/logs/proxmox-cli-YYYYMMDD-HHMMSS.jsonl
```

Optional latest pointer/copy:

```text
scripts/logs/latest.jsonl
```

### 13.3 Required Log Fields

Each command log should include:

```json
{
  "timestamp": "2026-07-06T19:00:00-04:00",
  "event": "api_call",
  "argv": ["vm", "status", "--node", "pve1", "--vmid", "101"],
  "dry_run": false,
  "method": "GET",
  "endpoint": "/nodes/pve1/qemu/101/status/current",
  "status_code": 200,
  "duration_ms": 123,
  "ok": true,
  "response_summary": "status=running name=test-vm vmid=101",
  "error": null
}
```

### 13.4 Redaction Rules

The logger must redact:

- API token secret.
- Full Authorization header.
- Password-like fields.
- Any `.env` value containing `SECRET`, `TOKEN`, `PASSWORD`, or `KEY`.

Example redaction:

```text
PVEAPIToken=agent@pve!opencode=********
```

### 13.5 Human Debugging Value

A second agent should be able to inspect the logs and answer:

- What command was run?
- What endpoint was called?
- Did it succeed?
- How long did it take?
- Was it dry-run or real execution?
- What task ID was returned?
- What failed?

## 14. Output Requirements

### 14.1 Default Output

Default output should be markdown because it is agent-readable and human-readable.

Example:

```md
## VM Status

- Node: pve1
- VMID: 101
- Name: ubuntu-test
- Status: running
- Uptime: 3h 12m
- CPU: 4.2%
- Memory: 2.1 GiB / 4 GiB
```

### 14.2 JSON Output

JSON output must always include:

```json
{
  "ok": true,
  "data": {},
  "error": null
}
```

### 14.3 Table Output

Table output is intended for humans and demos.

Example:

```text
VMID  NAME          NODE  STATUS   CPU    MEM
101   ubuntu-test   pve1  running  4.2%   2.1G/4G
102   debian-lab    pve1  stopped  0.0%   0G/2G
```

## 15. Error Handling

Errors must be clear, structured, and logged.

### 15.1 Common Error Cases

- Missing `.env`.
- Missing API URL.
- Missing token ID.
- Missing token secret.
- Invalid URL.
- SSL verification failure.
- Timeout.
- HTTP 401/403 auth failure.
- HTTP 404 endpoint/resource not found.
- Proxmox task failed.
- Safety guard blocked operation.
- JSON parse failure.

### 15.2 Error Output Shape

Markdown:

```md
## Error

- Type: auth_failure
- Message: Proxmox rejected the API token.
- Hint: Check PROXMOX_API_TOKEN_ID, token secret, and token ACL permissions.
- Log: scripts/logs/proxmox-cli-20260706-190000.jsonl
```

JSON:

```json
{
  "ok": false,
  "error": {
    "type": "auth_failure",
    "message": "Proxmox rejected the API token.",
    "hint": "Check token ID, token secret, and ACL permissions."
  },
  "data": null
}
```

## 16. AGENTS.md Requirements

`AGENTS.md` must include:

- Project purpose.
- Setup steps.
- `.env` instructions.
- Safe command examples.
- Write command safety rules.
- Logging rules.
- Bug tracking rules.
- Improvement tracking rules.
- Testing instructions.
- A “before changing code” checklist.
- A “after changing code” checklist.

### 16.1 Agent Bug Tracking Rule

When an agent finds a bug, it must add an entry to:

```text
scripts/BUGS.md
```

Bug entry format:

```md
## YYYY-MM-DD — Short bug title

- Status: open | fixed | cannot-reproduce
- Found by: agent/human
- Command:
- Expected:
- Actual:
- Suspected cause:
- Fix notes:
- Related log file:
```

### 16.2 Agent Improvement Tracking Rule

When an agent notices an improvement, it must add an entry to:

```text
scripts/IMPROVEMENTS.md
```

Improvement entry format:

```md
## YYYY-MM-DD — Short improvement title

- Status: proposed | accepted | implemented | rejected
- Area: cli | docs | logging | safety | tests | api
- Reason:
- Suggested change:
- Tradeoffs:
- Related files:
```

## 17. README.md Requirements

`README.md` must explain:

- What the project is.
- Why it exists.
- Who it is for.
- What problem it solves for agents.
- How the folder layout works.
- Why logs live under `scripts/logs/`.
- Why credentials live in `.env`.
- Why bugs and improvements are tracked in markdown.
- Basic quickstart commands.
- Safety warning for write operations.

## 18. docs/proxmox-api-notes.md Requirements

This file should track implementation notes such as:

- Auth header format.
- Common endpoint patterns.
- VM endpoints.
- LXC endpoints.
- Task endpoint behavior.
- Snapshot endpoint behavior.
- Permission and ACL notes.
- SSL verification notes.
- Known Proxmox version differences.
- Endpoint examples that were tested.

## 19. Python Implementation Requirements

### 19.1 Suggested Dependencies

Prefer minimal dependencies.

Recommended:

```text
requests
python-dotenv
```

Optional:

```text
rich
pytest
responses
```

If avoiding dependencies, use standard-library modules:

```text
argparse
json
os
pathlib
ssl
time
datetime
urllib.request
urllib.error
```

### 19.2 Suggested Modules Inside One File

Since the first version is a single script, organize it with clear sections:

```python
# constants
# env loading
# redaction helpers
# logging helpers
# API client
# output formatters
# safety guards
# command handlers
# argparse setup
# main
```

### 19.3 Naming

The user requested:

```text
scripts/Proxmox-cli.py
```

Keep that filename for compatibility with the requested layout, even though Python projects commonly prefer lowercase filenames.

## 20. Data Model

### 20.1 API Result Object

Internally normalize responses to:

```python
{
    "ok": True,
    "status_code": 200,
    "method": "GET",
    "endpoint": "/version",
    "data": {},
    "error": None,
    "duration_ms": 0,
}
```

### 20.2 Dry Run Result Object

```python
{
    "ok": True,
    "dry_run": True,
    "would_call": {
        "method": "POST",
        "endpoint": "/nodes/pve1/qemu/101/status/start",
        "body": {}
    },
    "message": "Dry run only. Re-run with --execute to apply."
}
```

## 21. Testing Plan

### 21.1 Unit Tests

Test:

- `.env` loading.
- Missing config behavior.
- Auth header construction.
- Secret redaction.
- Argparse command parsing.
- Dry-run blocking.
- Destructive guard behavior.
- Output formatters.
- Log writing.

### 21.2 Fake API Tests

Use a mocked HTTP server or request-mocking library to test:

- Successful `GET /version`.
- 401 auth failure.
- 403 permission failure.
- 404 missing VM.
- 500 Proxmox error.
- Timeout.
- Task ID returned by write command.

### 21.3 Live Integration Tests

Live tests must be opt-in only.

Suggested command:

```bash
python scripts/Proxmox-cli.py doctor --live
```

Live write tests must require a dedicated test VM/LXC ID and explicit execution flags.

## 22. Positive Test Cases

- `doctor` succeeds with valid config.
- `health` returns version, cluster, and node data.
- `nodes list --format json` returns top-level `ok: true`.
- `vms list --node pve1` lists QEMU guests.
- `vm status --node pve1 --vmid 101` returns status.
- `vm start --node pve1 --vmid 101` dry-runs by default.
- `vm start --node pve1 --vmid 101 --execute` calls the API.
- Write command with `--wait` polls the returned task.
- Logs are written to `scripts/logs/`.
- Token secret is redacted in all logs.

## 23. Negative Test Cases

- Missing `.env` returns exit code `2`.
- Missing token secret returns exit code `2`.
- Invalid API URL returns exit code `2`.
- Auth failure returns exit code `3`.
- Proxmox 500 response returns exit code `4`.
- Timeout returns exit code `5`.
- `vm stop` without `--execute` is dry-run only.
- `vm stop --execute` without `--force` is blocked.
- `vm stop --execute --force` without `--confirm <vmid>` is blocked.
- `api delete` without destructive guards is blocked.
- Logs must not contain the real token secret after any failure.

## 24. Security Requirements

- Never print full API token secrets.
- Never log full Authorization headers.
- Keep `.env` out of git.
- Prefer dedicated low-privilege Proxmox API users.
- Prefer separated token privileges with explicit ACLs.
- Prefer token expiration for lab automation tokens.
- Default SSL verification to enabled.
- Make insecure SSL mode noisy.
- Avoid bulk destructive actions.

## 25. Documentation Requirements

Before v1 is considered complete, the repo must include:

- `README.md`
- `AGENTS.md`
- `.env.example`
- `spec.md`
- `docs/proxmox-api-notes.md`
- `scripts/BUGS.md`
- `scripts/IMPROVEMENTS.md`

## 26. v1 Acceptance Criteria

v1 is complete when:

- The folder layout matches the requested structure plus bug/improvement trackers.
- `.env.example` documents all required config.
- `doctor`, `health`, `nodes list`, `vms list`, `vm status`, and `api get` work.
- Logs are created under `scripts/logs/`.
- Logs redact secrets.
- Write commands dry-run by default.
- Write commands require `--execute`.
- Destructive commands require `--execute --force --confirm <id>`.
- `README.md` explains what and why.
- `AGENTS.md` explains how agents should use and maintain the project.
- Bugs and improvements are tracked in markdown inside `scripts/`.

## 27. Future Enhancements

- Add VM creation from templates.
- Add cloud-init helpers.
- Add backup commands.
- Add ISO upload helpers.
- Add storage health summaries.
- Add HA status commands.
- Add cluster firewall inspection.
- Add Markdown report generation for YouTube/demo runs.
- Add shell completion.
- Add a safe “plan file” mode where agents generate a plan first, then execute approved steps.
