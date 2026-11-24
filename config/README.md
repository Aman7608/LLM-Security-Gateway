# config

Rule and policy files that can be changed without touching the code. The gateway reads them at startup. The policy can also be changed while it runs (from the dashboard or `PUT /v1/policies/active`).

| File | What it holds | Phase | Guide |
|---|---|---|---|
| `policy.yaml` | What to do with each finding (allow, warn, redact, block), for prompts and for answers | 9 | [10-policy-engine.md](../docs/10-policy-engine.md) |
| `injection_rules.yaml` | Prompt injection patterns, with categories and confidence | 5 | [06-prompt-injection-detection.md](../docs/06-prompt-injection-detection.md) |
| `pii_entities.yaml` | Which kinds of personal data to look for, and how sure the detector must be | 6 | [07-pii-detection.md](../docs/07-pii-detection.md) |
| `secret_patterns.yaml` | API key, token and password patterns | 7 | [08-secret-detection.md](../docs/08-secret-detection.md) |
| `confidential_terms.yaml` | Your secret project names and "confidential" markings. **Replace the examples with your own** | 11 | [12-output-scanner.md](../docs/12-output-scanner.md) |
| `examples/strict-policy.yaml` | A stricter example policy | 9 | [10-policy-engine.md](../docs/10-policy-engine.md) |

Which files are used is set in `.env` (see [settings.md](../docs/settings.md)).

Secrets never go in this folder. They go in `.env`, which git ignores.
