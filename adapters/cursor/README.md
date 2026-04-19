# cursor adapter

**status:** community port welcome — currently not maintained by this repo.

cursor doesn't expose a hook system equivalent to claude code's `PreToolUse/PostToolUse`. the patterns in `hooks/` can still be used as:

- **pre-commit hooks** (git) — L3 secrets-scanner works as-is
- **shell aliases** — wrap `curl/wget/nc` through `hooks/network-egress.sh`
- **cron check** — periodic `integrity-check.sh verify`

contributions welcome. open an issue or PR with `adapter: cursor` tag.
