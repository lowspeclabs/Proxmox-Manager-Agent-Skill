# IMPROVEMENTS.md

Track proposed improvements while developing or using `scripts/Proxmox-cli.py`.

## Template

```md
## YYYY-MM-DD — Short improvement title

- Status: proposed | accepted | implemented | rejected
- Area: cli | docs | logging | safety | tests | api
- Reason:
- Suggested change:
- Tradeoffs:
- Related files:
```

## Status

No open improvements.

## Implemented improvements

- **VM/LXC snapshot commands** — `vm snapshot list/create/delete` and `lxc snapshot list/create/delete`.
- **Formal unit tests** — `tests/test_cli.py` with `tests/mock_proxmox.py`.
- **prompt.md compatibility** — flat aliases (`status`, `nodes`, `vms`, `containers`, etc.) and `--yes` as alias for `--execute`, plus `.env` fallback formats.
- **VM/LXC create and delete** — `vm create/delete` and `lxc create/delete` with dry-run and destructive guards.
- **Lookup and discovery** — `network list`, `storage templates`, `storage template-download`, `vms next-id`, `lxcs next-id`.
- **AGENTS.md documentation** — usage examples for discovery, read-only, write, and destructive commands.
