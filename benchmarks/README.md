# benchmarks

reproducible tests proving each layer catches its attack vector.

## run

```bash
bash benchmarks/adversarial.sh
```

## what it tests

- **L1** — 4 injection patterns (jailbreak, zero-width unicode, pipe-to-shell, mcp response)
- **L2** — 2 blocked destinations + 1 allowed destination (negative control)
- **L3** — 3 block cases (Write, Write, NotebookEdit) + 1 fixtures-path exemption
- **L5** — 3 cases: jailbreak prompt, secret-in-prompt, clean prompt
- **L6** — 3 cases: bad-host MCP call, secret-in-MCP-args, allowed-host MCP call
- **L4** — integrity manifest verification

## expected baseline

```
⬡ aegis adversarial suite

  ✓ L1 · jailbreak in page          · 19ms
  ✓ L1 · zero-width unicode         · 26ms
  ✓ L1 · pipe-shell in page         · 37ms
  ✓ L1 · mcp response poisoned      · 32ms
  ✓ L2 · curl to blocked host       · 24ms
  ✓ L2 · nc reverse shell           · 18ms
  ✓ L2 · curl to github             · 20ms
  ✓ L3 · aws key in Write           · 22ms
  ✓ L3 · anthropic key in Write     · 32ms
  ✓ L3 · NotebookEdit with key      · 32ms
  ✓ L3 · key in fixtures/           · 25ms
  ✓ L5 · task prompt jailbreak      · 39ms
  ✓ L5 · task prompt secret         · 44ms
  ✓ L5 · task prompt clean          · 29ms
  ✓ L6 · mcp call to bad host       · 27ms
  ✓ L6 · mcp call with secret       · 30ms
  ✓ L6 · mcp call allowed host      · 41ms

L4 · integrity-manifest
    ✅ 32 archivos íntegros

summary  pass=17  fail=0
```

## latency

| hook | p50 | p99 |
|---|---|---|
| L1 injection-detector | 8ms | 38ms |
| L2 network-egress | 4ms | 24ms |
| L3 secrets-scanner | 9ms | 32ms |
| L4 integrity (32 files) | 140ms | — |
| L5 agent-spawn-guard | 10ms | 44ms |
| L6 mcp-interceptor | 12ms | 43ms |

cache-transparent: hooks run in a subshell, do not modify the model's context or token counters.
