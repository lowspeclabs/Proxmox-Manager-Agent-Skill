# AGENTS.md — Proxmox CLI Agent Guide

This file is the operating guide for agents working on `proxmox-opencode-lab`.

## Mission

Maintain a safe CLI wrapper that allows an agent harness to inspect and manage Proxmox VE through predictable commands, `.env` configuration, strong logging, and explicit safety guards.

## First Steps for Any Agent

1. Read `README.md`.
2. Read `spec.md`.
3. Check `.env.example` but never print or expose real `.env` secrets.
4. Inspect `scripts/BUGS.md`.
5. Inspect `scripts/IMPROVEMENTS.md`.
6. Run read-only checks before any write command.

## Setup

```bash
cp .env.example .env
python scripts/Proxmox-cli.py doctor
```

Required `.env` values:

```dotenv
PROXMOX_API_URL=https://proxmox.example.local:8006/api2/json
PROXMOX_API_TOKEN_ID=agent@pve!opencode
PROXMOX_API_TOKEN_SECRET=replace-me
```

Never commit `.env`.

## Common Read-Only Commands

```bash
python scripts/Proxmox-cli.py doctor
python scripts/Proxmox-cli.py health
python scripts/Proxmox-cli.py nodes list
python scripts/Proxmox-cli.py node status --node pve1
python scripts/Proxmox-cli.py vms list --node pve1
python scripts/Proxmox-cli.py vm status --node pve1 --vmid 101
python scripts/Proxmox-cli.py vm config --node pve1 --vmid 101
python scripts/Proxmox-cli.py storage list --node pve1
python scripts/Proxmox-cli.py tasks recent --node pve1
```

## Lookup / Discovery Commands

Use these to discover IDs, networks, storage, and templates before creating resources.

```bash
# Next free VM/container ID
python scripts/Proxmox-cli.py vms next-id
python scripts/Proxmox-cli.py lxcs next-id

# Networks (bridges, VLANs, physical interfaces)
python scripts/Proxmox-cli.py network list --node pve1

# Storage and content
python scripts/Proxmox-cli.py storage list --node pve1
python scripts/Proxmox-cli.py storage content --node pve1 --storage local

# LXC templates available on a storage pool
python scripts/Proxmox-cli.py storage templates --node pve1 --storage local

# Download an LXC template from a URL (state-changing, dry-run by default)
python scripts/Proxmox-cli.py storage template-download --node pve1 --storage local \
  --url https://example.com/debian-12-standard.tar.zst \
  --filename debian-12-standard.tar.zst

# Print Debian 13 LXC console workaround for an existing container
python scripts/Proxmox-cli.py lxc fix-console --node pve1 --vmid 109
```

## LXC SSH Key Management

Generate and inject SSH keys for LXC containers. Generated keys are stored on the machine running the CLI, not in the Proxmox API, and private keys are kept out of logs.

```bash
# Generate a new Ed25519 key pair for a specific container
python scripts/Proxmox-cli.py lxc ssh-keygen --vmid 110 --keyfile ~/.ssh/lxc-110

# Create an LXC container and inject an existing public key
python scripts/Proxmox-cli.py lxc create --node pve1 --vmid 110 \
  --hostname my-container \
  --ostemplate local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --storage local-lvm \
  --ssh-public-keys "ssh-ed25519 AAAAC3... user@host"

# Create an LXC container and generate + inject a fresh key on the fly
python scripts/Proxmox-cli.py lxc create --node pve1 --vmid 110 \
  --hostname my-container \
  --ostemplate local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --storage local-lvm \
  --ssh-keygen --ssh-key-path ~/.ssh/lxc-110
```

Notes:
- Debian/Ubuntu LXC templates typically disable root password SSH login, so key injection is the preferred way to access the container.
- `--ssh-keygen` only writes files when `--execute` is used; in dry-run mode the container is not created and no key is generated.
- The generated public key is placed in `~/.ssh/lxc-110.pub`; use `ssh -i ~/.ssh/lxc-110 root@<container-ip>` to connect.

## Write Command Rules

State-changing commands must dry-run by default.

Dry-run example:

```bash
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101
```

Real execution example:

```bash
python scripts/Proxmox-cli.py vm start --node pve1 --vmid 101 --execute --wait
```

Dangerous execution example:

```bash
python scripts/Proxmox-cli.py vm stop --node pve1 --vmid 101 --execute --force --confirm 101
```

Do not bypass safety guards.

## Prompt.md Compatibility

For compatibility with the original `prompt.md` planning file, the CLI also accepts these flat aliases and `--yes` as an alias for `--execute` on write commands:

- `status` → `health`
- `nodes` → `nodes list`
- `vms` → `vms list`
- `containers` → `lxcs list`
- `vm-status` → `vm status`
- `container-status` → `lxc status`
- `start-vm` → `vm start`
- `reboot-vm` → `vm reboot`
- `stop-vm` → `vm stop`

Destructive aliases still require the full `--execute --force --confirm <vmid>` guard, with `--yes` usable in place of `--execute`. The `.env` loader also falls back to `PROXMOX_HOST`/`PROXMOX_PORT` and `PROXMOX_API_USER`/`PROXMOX_API_TOKEN_ID` formats.

## Logging Rules

All commands should log to:

```text
scripts/logs/
```

Logs must include:

- command argv,
- dry-run status,
- API method,
- endpoint,
- status code,
- duration,
- success/failure,
- task ID if returned,
- redacted error details.

Logs must never include:

- token secrets,
- full Authorization headers,
- passwords,
- private keys.

## Bug Tracking

When you find a bug, update:

```text
scripts/BUGS.md
```

Use this format:

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

## Improvement Tracking

When you notice a useful improvement, update:

```text
scripts/IMPROVEMENTS.md
```

Use this format:

```md
## YYYY-MM-DD — Short improvement title

- Status: proposed | accepted | implemented | rejected
- Area: cli | docs | logging | safety | tests | api
- Reason:
- Suggested change:
- Tradeoffs:
- Related files:
```

## Before Changing Code

- Read the relevant section of `spec.md`.
- Check existing bugs and improvements.
- Prefer small, testable changes.
- Preserve safety defaults.
- Do not add new dependencies unless they clearly reduce complexity.

## After Changing Code

- Run the safest available tests.
- Run `doctor` if a live `.env` is available.
- Test at least one read-only command.
- Confirm logs are created and secrets are redacted.
- Update `scripts/BUGS.md` or `scripts/IMPROVEMENTS.md` when appropriate.
- Summarize what changed and why.
