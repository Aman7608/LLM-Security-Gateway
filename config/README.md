# config

Rule and policy files that can be changed without touching the code.

These files are added in later phases:

| File | What it holds | Phase |
|---|---|---|
| `injection_rules.yaml` | Prompt injection patterns | 5 |
| `pii_entities.yaml` | Which PII types to look for, and confidence thresholds | 6 |
| `secret_patterns.yaml` | API key, token and password patterns | 7 |
| `policy.yaml` | What to do with each finding (allow, warn, redact, block) | 9 |

Secrets never go in this folder. They go in `.env`, which git ignores.
