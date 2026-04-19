#!/usr/bin/env bash
# mcp-interceptor.sh — PreToolUse(mcp__*):
# Intercepta llamadas a MCP tools: extrae URLs → valida contra allowlist,
# escanea args por secretos, logea la llamada completa.
# Exit 2 bloquea. Allowlist compartida con L2.
set -uo pipefail

PAYLOAD=$(cat)
[[ -z "$PAYLOAD" ]] && exit 0

ALLOWLIST="$HOME/.claude/config/network-allowlist.txt"
LOG="$HOME/.claude/memory/mcp-calls.jsonl"
mkdir -p "$HOME/.claude/memory" "$(dirname "$ALLOWLIST")"

HOOK_PAYLOAD="$PAYLOAD" HOOK_ALLOW="$ALLOWLIST" HOOK_LOG="$LOG" python3 <<'PYEOF'
import sys, json, os, re
from datetime import datetime

raw = os.environ.get("HOOK_PAYLOAD", "")
allow_path = os.environ.get("HOOK_ALLOW", "")
log_path = os.environ.get("HOOK_LOG", "")
if not raw: sys.exit(0)

try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)

tool_name = data.get("tool_name", "")
if not tool_name.startswith("mcp__"):
    sys.exit(0)

tool_input = data.get("tool_input", {}) or {}

# Recoger todos los strings del input recursivamente
def collect_strings(obj, out):
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values(): collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj: collect_strings(v, out)

strings = []
collect_strings(tool_input, strings)
blob = "\n".join(strings)

# 1. Extraer URLs → validar contra allowlist
allow = set()
try:
    for line in open(allow_path):
        line = line.strip()
        if line and not line.startswith("#"):
            allow.add(line.lower())
except Exception:
    pass

def is_allowed(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}: return True
    if re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)", host): return True
    for a in allow:
        if host == a or host.endswith("." + a):
            return True
    return False

hosts = set()
for m in re.finditer(r"(?:https?|ftp|ftps)://([^/\s\"'\\]+)", blob, re.IGNORECASE):
    host = m.group(1).split(":")[0].split("@")[-1]
    hosts.add(host.lower())

bad_hosts = [h for h in hosts if not is_allowed(h)]

# 2. Secrets en args
SECRETS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS:access-key-id"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub:PAT"),
    (r"\bsk-ant-[A-Za-z0-9\-_]{40,}\b", "Anthropic:apiKey"),
    (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI:apiKey"),
    (r"-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE\s+KEY-----", "SSH:privateKey"),
    (r"\bAIza[0-9A-Za-z\-_]{35}\b", "Google:APIKey"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack:token"),
    (r"(?i)(postgres|mysql|mongodb)(\+\w+)?://[^:\s]+:[^@\s]{4,}@", "DB:conn-with-password"),
]
sec_hits = []
for pat, tag in SECRETS:
    try:
        m = re.search(pat, blob)
        if m: sec_hits.append({"tag": tag})
    except re.error:
        continue

# Log siempre — audit trail
entry = {
    "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "mcp_tool": tool_name,
    "hosts": sorted(hosts),
    "blocked_hosts": sorted(bad_hosts),
    "secret_tags": [h["tag"] for h in sec_hits],
    "input_keys": sorted(tool_input.keys()) if isinstance(tool_input, dict) else [],
}
try:
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
except Exception:
    pass

# Decidir bloqueo
if not bad_hosts and not sec_hits:
    sys.exit(0)

msg = [f"🔌 MCP CALL BLOCKED [{tool_name}]"]
if bad_hosts:
    msg.append(f"   Hosts fuera de allowlist: {sorted(bad_hosts)}")
if sec_hits:
    msg.append(f"   Secretos en args: {sorted({h['tag'] for h in sec_hits})}")
msg.append(f"   → Si es legítimo: añadir host a {allow_path} o mover secret a env.")
msg.append(f"   → Si no: posible exfiltración vía MCP server.")
msg.append(f"   Log: ~/.claude/memory/mcp-calls.jsonl")
print("\n".join(msg), file=sys.stderr)
sys.exit(2)
PYEOF
