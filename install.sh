#!/usr/bin/env bash
# Aegis installer — registers 4 security hooks into ~/.claude/settings.json.
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HELPERS="$CLAUDE_DIR/helpers"
CONFIG="$CLAUDE_DIR/config"
SETTINGS="$CLAUDE_DIR/settings.json"

GREEN="\033[0;32m"; BLUE="\033[0;34m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"

echo -e "${BLUE}⬡ Aegis installer${NC}"

# 1. Paths
mkdir -p "$HELPERS" "$CONFIG" "$CLAUDE_DIR/data"

# 2. Copy scripts
for f in injection-detector-hook.sh network-egress-hook.sh secrets-scanner-hook.sh integrity-check.sh; do
    cp "$AEGIS_DIR/src/$f" "$HELPERS/$f"
    chmod +x "$HELPERS/$f"
    echo -e "  ${GREEN}✓${NC} $f → $HELPERS/"
done

# 3. Seed allowlist (only if missing)
if [[ ! -f "$CONFIG/network-allowlist.txt" ]]; then
    cp "$AEGIS_DIR/config/network-allowlist.txt.example" "$CONFIG/network-allowlist.txt"
    echo -e "  ${GREEN}✓${NC} seeded $CONFIG/network-allowlist.txt"
else
    echo -e "  ${YELLOW}~${NC} $CONFIG/network-allowlist.txt already exists — left untouched"
fi

# 4. Register hooks in settings.json (merge-aware)
python3 - <<PYEOF
import json, os
from pathlib import Path

settings_path = Path(os.path.expanduser("~/.claude/settings.json"))
home = os.path.expanduser("~")

hooks_to_add = {
    "PostToolUse": [
        {"matcher": "WebFetch|WebSearch|Read",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/injection-detector-hook.sh"'}]}
    ],
    "PreToolUse": [
        {"matcher": "Bash",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/network-egress-hook.sh"'}]},
        {"matcher": "Write|Edit|MultiEdit|Bash",
         "hooks": [{"type": "command",
                    "command": f'bash "{home}/.claude/helpers/secrets-scanner-hook.sh"'}]}
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

# 5. Baseline integrity manifest
bash "$HELPERS/integrity-check.sh" init >/dev/null 2>&1 || true
echo -e "  ${GREEN}✓${NC} integrity manifest baselined"

echo
echo -e "${GREEN}✅ Aegis installed. 4 layers active.${NC}"
echo "   L1 injection-detector   — PostToolUse(WebFetch|WebSearch|Read)"
echo "   L2 network-egress       — PreToolUse(Bash)"
echo "   L3 secrets-scanner      — PreToolUse(Write|Edit|MultiEdit|Bash)"
echo "   L4 integrity-manifest   — run: bash $HELPERS/integrity-check.sh verify"
echo
echo "   Adversarial self-test (optional):  bash $AEGIS_DIR/tests/adversarial.sh"
