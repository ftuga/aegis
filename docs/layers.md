# the 6 layers

## L1 — injection-detector

**fires on:** `PostToolUse` for `WebFetch`, `WebSearch`, `Read`, `mcp__.*`
**action:** advisory (logs + stderr alert)
**why advisory:** the content is already in the agent's context. blocking after-the-fact doesn't help. what we can do is *flag loudly* so the agent (and you) know the content is untrusted.

**patterns caught:**
- jailbreak: `ignore previous`, `disregard (all )?instructions`, `role: system`, fake `</system>` tags, `you are now`, DAN-style resets
- exec: `curl … | bash/sh`, `wget -O- | sh`, `nc -e`, `eval(base64|atob`, `/etc/passwd`, `~/.ssh/`, `AKIA[0-9A-Z]{16}`
- hidden: zero-width chars (U+200B/C/D/FEFF), base64 blobs ≥250 chars, bidirectional overrides

**log:** `~/.claude/memory/injection-alerts.jsonl`

---

## L2 — network-egress

**fires on:** `PreToolUse` for `Bash`
**action:** block (exit 2) if destination not in allowlist

**parses:** `curl`, `wget`, `nc`, `netcat`, `ncat`, `ssh`, `scp`, `rsync`, `ftp`, `sftp`, `git clone`

**extraction:** URLs, `user@host:` forms, raw `nc host port`

**allowlist format** (`~/.claude/config/network-allowlist.txt`):
```
github.com            # exact
*.githubusercontent.com  # suffix
10.*                  # CIDR-like glob
```

default seeded with: github, pypi, npm registry, docker.io, anthropic, localhost, private IP ranges.

---

## L3 — secrets-scanner

**fires on:** `PreToolUse` for `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash`
**action:** block (exit 2) if pattern match + target not in safe-list

**patterns:** AWS, GCP, GitHub tokens, OpenAI, Anthropic, Slack, Stripe, Google API, SSH private keys, JWT signed, DB conn-with-password

**safe-targets** (never blocked):
- `.env.example`, `.env.sample`
- `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`
- `README*`, `docs/`, `*.md`
- aegis internals + log files

**bash parsing:** handles heredocs (`<<EOF ... EOF`) and `echo ... > file` patterns.

---

## L4 — integrity-manifest

**fires:** manual / cron
**action:** report drift (colored diff)

**commands:**
```bash
integrity-check.sh init     # baseline
integrity-check.sh verify   # compare current vs baseline
integrity-check.sh update   # rebaseline (after legitimate change)
```

**tracked files:** `settings.json`, `CLAUDE.md`, every `helpers/*.sh`. auto-picks up new hooks as they're added.

---

## L5 — agent-spawn-guard

**fires on:** `PreToolUse` for `Task`
**action:** block (exit 2) if injection patterns OR secrets found in subagent prompt

**why it matters:** `Task` spawns a subagent with a prompt string. If that prompt was built from `WebFetch` output, it may carry hostile instructions — and the subagent will execute them, because to the subagent *that IS the system prompt*.

**catches:**
- injection: jailbreak, fake system tags, new-instructions, pipe-to-shell, eval-b64, zero-width unicode
- secrets: AWS key, GitHub PAT, Anthropic/OpenAI keys, SSH private key, Google API key — filtered into subagent context

**log:** `~/.claude/memory/agent-spawn.jsonl` — full audit trail of every `Task` invocation (subagent type, description, prompt length, hits). Match literals are NOT persisted for secrets.

---

## L6 — mcp-interceptor

**fires on:** `PreToolUse` for any tool matching `mcp__.*`
**action:** block (exit 2) if URL not in allowlist OR secret found in args

**why it matters:** MCP servers run as separate processes. Their network egress doesn't go through `Bash`, so L2 can't see it. But the *call itself* — the tool arguments — passes through Claude Code. Inspect them before they leave.

**extracts:** all strings from `tool_input` recursively. URLs → matched against the same allowlist as L2. All strings → matched against L3's secret patterns.

**typical catches:**
- `mcp__gmail__send` with an API key in the body
- `mcp__fetch__get` with a URL pointing to an exfiltration host
- `mcp__filesystem__write` with a secret in the content

**log:** `~/.claude/memory/mcp-calls.jsonl` — audit trail of every MCP invocation (tool name, hosts seen, blocked hosts, secret tags).

**limitation:** L6 inspects the *call*. It cannot inspect what the MCP server does internally. If the MCP server itself is malicious, aegis can't help — trust your MCP servers or sandbox them.
