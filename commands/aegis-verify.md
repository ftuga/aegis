---
description: Run Aegis integrity check + report drift in Claude Code configuration
allowed-tools: Bash(bash:*)
---

Run the Aegis integrity check and report results.

```bash
bash ~/.claude/helpers/integrity-check.sh verify
```

If drift is detected, explain:
1. Which files changed (and whether the change appears legitimate)
2. Whether to rebaseline with `integrity-check.sh update` or investigate
3. Cross-reference recent legitimate changes (git log, recent evolutions)

Output concise: headline + bullet per changed file + single-line recommendation.
