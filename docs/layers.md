# the 4 layers

## L1 — injection-detector

**fires on:** `PostToolUse` for `WebFetch`, `WebSearch`, `Read`
**action:** advisory (logs + stderr alert)
**why advisory:** the content is already in the agent's context. blocking after-the-fact doesn't help. what we can do is *flag loudly* so the agent (and you) know the content is untrusted.

**patterns caught:**
- jailbreak: `ignore previous`, `disregard (all )?instructions`, `role: system`, fake `</system>` tags, `you are now`, `DAN mode`
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

**fires on:** `PreToolUse` for `Write`, `Edit`, `MultiEdit`, `Bash`
**action:** block (exit 2) if pattern match + target not in safe-list

**patterns:** AWS, GCP, GitHub tokens, OpenAI, Anthropic, Slack, Stripe, Google API, SSH private keys, JWT signed, DB conn-with-password

**safe-targets** (never blocked):
- `.env.example`, `.env.sample`
- `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`
- `README*`, `docs/`, `*.md`
- aegis internals

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

**tracked files:** `settings.json`, `CLAUDE.md`, every `helpers/*.sh`. customize in `integrity-check.sh` `TRACKED` array.
