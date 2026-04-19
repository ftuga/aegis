# benchmarks

reproducible tests proving each layer catches its attack vector.

## run

```bash
bash benchmarks/adversarial.sh
```

## what it tests

- **L1** — 3 injection patterns (jailbreak, zero-width unicode, pipe-to-shell)
- **L2** — 2 blocked destinations + 1 allowed destination (negative control)
- **L3** — 2 secret literals + 1 fixtures-path (safe-target exemption)
- **L4** — integrity manifest verification

## expected baseline

```
⬡ aegis adversarial suite

  ✓ L1 · jailbreak in page · 8ms
  ✓ L1 · zero-width payload · 11ms
  ✓ L1 · pipe-shell in page · 9ms
  ✓ L2 · curl to blocked host · 4ms
  ✓ L2 · nc reverse shell · 5ms
  ✓ L2 · curl to github · 3ms
  ✓ L3 · aws key · 9ms
  ✓ L3 · anthropic key · 12ms
  ✓ L3 · key in fixture path · 6ms

L4 · integrity-manifest
    ✅ 29 archivos íntegros

summary  pass=9  fail=0
```

## latency

| hook | p50 | p99 |
|---|---|---|
| L1 injection-detector | 8ms | 22ms |
| L2 network-egress | 4ms | 11ms |
| L3 secrets-scanner | 9ms | 28ms |
| L4 integrity (29 files) | 140ms | — |

cache-transparent: hooks run in a subshell, do not modify the model's context or token counters.
