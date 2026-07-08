# proxmox-opencode-lab

`proxmox-opencode-lab` is an agent-friendly CLI wrapper for managing a Proxmox VE lab through stable, logged, safety-guarded commands.

The project is designed for OpenCode-style agent harnesses and small local models that need to inspect or manage Proxmox without hand-writing brittle raw API calls every time.

## Why This Exists

Direct Proxmox API calls are powerful, but they are easy for agents to misuse. This project gives agents a safer interface with:

- predictable commands,
- markdown and JSON output,
- dry-run defaults for write actions,
- explicit destructive-operation guards,
- `.env`-based API configuration,
- command/result logging,
- markdown bug and improvement tracking.

## Recommended Layout

```text
proxmox-opencode-lab/
├─ AGENTS.md
├─ README.md
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

## Layout Rationale

- `scripts/Proxmox-cli.py` is the main executable so agent harnesses can find it quickly.
- `scripts/logs/` keeps command logs beside the tool that generated them.
- `.env` stores local API secrets outside source control.
- `.env.example` documents the config without exposing real secrets.
- `AGENTS.md` tells future agents exactly how to operate and maintain the project.
- `scripts/BUGS.md` and `scripts/IMPROVEMENTS.md` create durable project memory for future agent runs.
- `docs/proxmox-api-notes.md` stores endpoint notes and Proxmox-specific gotchas.

## Quickstart

```bash
cp .env.example .env
python scripts/Proxmox-cli.py doctor
python scripts/Proxmox-cli.py health
python scripts/Proxmox-cli.py nodes list
python scripts/Proxmox-cli.py vms list --node pve1
```

State-changing commands must dry-run by default and require explicit execution flags.

```bash
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101 --execute --wait
```

Dangerous operations require stronger guards.

```bash
python scripts/Proxmox-cli.py vm stop --node pve1 --vmid 101 --execute --force --confirm 101
```

## Safety Rule

Read first. Dry-run second. Execute only after the intended node, VMID, endpoint, and action are clear.
