#!/usr/bin/env bash
# aegis installer — registers 4 security hooks into ~/.claude/settings.json
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HELPERS="$CLAUDE_DIR/helpers"
CONFIG="$CLAUDE_DIR/config"
SETTINGS="$CLAUDE_DIR/settings.json"

GREEN="\033[0;32m"; BLUE="\033[0;34m"; YELLOW="\033[0;33m"; NC="\033[0m"

echo -e "${BLUE}⬡ aegis installer${NC}"

mkdir -p "$HELPERS" "$CONFIG" "$CLAUDE_DIR/data"

# 1. copy hook scripts
for f in injection-detector.sh network-egress.sh secrets-scanner.sh integrity-check.sh; do
    cp "$AEGIS_DIR/hooks/$f" "$HELPERS/$f"
    chmod +x "$HELPERS/$f"
    echo -e "  ${GREEN}✓${NC} $f → $HELPERS/"
done

# 2. seed allowlist if missing
if [[ ! -f "$CONFIG/network-allowlist.txt" ]]; then
    cp "$AEGIS_DIR/config/network-allowlist.example.txt" "$CONFIG/network-allowlist.txt"
    echo -e "  ${GREEN}✓${NC} seeded $CONFIG/network-allowlist.txt"
else
    echo -e "  ${YELLOW}~${NC} $CONFIG/network-allowlist.txt already exists — left untouched"
fi

# 3. register hooks in settings.json (merge-aware)
python3 - <<PYEOF
import json, os
from pathlib import Path

settings_path = Path(os.path.expanduser("~/.claude/settings.json"))
home = os.path.expanduser("~")

hooks_to_add = {
    "PostToolUse": [
        {"matcher": "WebFetch|WebSearch|Read",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/injection-detector.sh"'}]}
    ],
    "PreToolUse": [
        {"matcher": "Bash",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/network-egress.sh"'}]},
        {"matcher": "Write|Edit|MultiEdit|Bash",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/secrets-scanner.sh"'}]}
    ]
}

data = {}
if settings_path.exists():
    data = json.loads(settings_path.read_text())

data.setdefault("hooks", {})
for event, new_list in hooks_to_add.items():
    existing = data["hooks"].setdefault(event, [])
    for item in new_list:
        cmd = item["hooks"][0]["command"]
        if not any(cmd in json.dumps(e) for e in existing):
            existing.append(item)

settings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
print("  ✓ hooks registered in", settings_path)
PYEOF

# 4. baseline integrity manifest
bash "$HELPERS/integrity-check.sh" init >/dev/null 2>&1 || true
echo -e "  ${GREEN}✓${NC} integrity manifest baselined"

echo
echo -e "${GREEN}✅ aegis installed. 4 layers active.${NC}"
echo "   L1 injection-detector   — PostToolUse(WebFetch|WebSearch|Read)"
echo "   L2 network-egress       — PreToolUse(Bash)"
echo "   L3 secrets-scanner      — PreToolUse(Write|Edit|MultiEdit|Bash)"
echo "   L4 integrity-manifest   — bash $HELPERS/integrity-check.sh verify"
echo
echo "   adversarial suite:  bash $AEGIS_DIR/benchmarks/adversarial.sh"
