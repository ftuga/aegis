# threat model

## what aegis defends against

| attack vector | layer | mechanism |
|---|---|---|
| prompt injection via webfetch | L1 | pattern scan of fetched content |
| prompt injection via local read | L1 | pattern scan of read content |
| unauthorized network egress | L2 | allowlist enforcement on `curl/wget/nc/ssh/git clone` |
| hardcoded secrets in writes | L3 | regex scan of Write/Edit/MultiEdit payloads |
| secrets in bash heredocs | L3 | heredoc + `echo > file` extraction |
| silent config tampering | L4 | SHA256 manifest of critical files |

## what aegis does NOT defend against

| attack | why out-of-scope | mitigation |
|---|---|---|
| model compliance with social engineering | no tool call to inspect | review agent output manually |
| supply-chain compromise of MCP server | aegis runs at tool-call boundary, not package layer | `sigstore`, `npm audit`, `pip-audit` |
| OS-level privilege escalation | requires kernel-level isolation | firejail, rootless containers, SELinux |
| side-channel (timing, cache) | requires HW-level mitigation | out of scope for any agent harness |
| content served over TLS (poisoned) | allowlist restricts destinations, not payloads | combine L1 with destination review |

## known limitations

1. **regex-based detection is not proof.** novel injection patterns not in our list will pass L1. the list evolves — see `hooks/injection-detector.sh`, `PATTERNS` array.
2. **bash parsing is heuristic.** exotic command constructs (eval chains, variable substitution from env) may evade L2/L3. defense-in-depth with claude code `permission_mode` is recommended.
3. **integrity manifest is local.** if the attacker can modify `~/.claude/data/integrity-manifest.json` they can mask tampering. store a hash of the manifest externally for high-assurance deployments.

## disclosure

found a bypass? open an issue or email security@ftuga.dev (coming).
