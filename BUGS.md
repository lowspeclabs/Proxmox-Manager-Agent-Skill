# BUGS.md

Track bugs discovered while developing or using `scripts/Proxmox-cli.py`.

## Template

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

## Status

No open bugs.

## Fixed bugs

- **Auth exit codes** — `_exit_code_for` now maps 401/403 to `EXIT_AUTH` and timeouts to `EXIT_TIMEOUT`.
- **Token permission errors** — The original API token had no effective privileges; switching to a correctly scoped token resolved storage and node-status failures.
