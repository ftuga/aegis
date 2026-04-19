# claude code adapter

default target. `install.sh` at repo root does everything:

1. copies `hooks/*.sh` → `~/.claude/helpers/`
2. copies `config/network-allowlist.example.txt` → `~/.claude/config/network-allowlist.txt` (if absent)
3. merges 3 hook entries into `~/.claude/settings.json`
4. baselines integrity manifest (L4)

## manual install

```bash
mkdir -p ~/.claude/helpers ~/.claude/config
cp hooks/*.sh ~/.claude/helpers/
cp config/network-allowlist.example.txt ~/.claude/config/network-allowlist.txt

# edit ~/.claude/settings.json and add under "hooks":
#   PostToolUse → matcher WebFetch|WebSearch|Read → injection-detector.sh
#   PreToolUse  → matcher Bash                    → network-egress.sh
#   PreToolUse  → matcher Write|Edit|MultiEdit|Bash → secrets-scanner.sh

bash ~/.claude/helpers/integrity-check.sh init
```
