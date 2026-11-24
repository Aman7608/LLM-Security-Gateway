# Settings Reference

Every setting of the gateway, in one place. A test (`tests/unit/test_docs.py`) checks that this page lists every setting in the code with the right default, so it can't go out of date.

## How settings are read

- Each setting is an **environment variable** that starts with `GATEWAY_`, for example `GATEWAY_PORT=8000`.
- They can also be written in a **`.env` file** in the project folder. Copy `.env.example` to `.env` to start. `.env` is never committed to Git.
- If a variable is set in the shell **and** in `.env`, the shell wins.
- Wrong values stop the gateway at startup with a clear message. For example, `GATEWAY_PORT=70000` gets "less than or equal to 65535".
- `scripts\serve.py` sets `GATEWAY_ENVIRONMENT=production` unless you set it in the shell (or use `--development`).
- The **rules** (what counts as an attack, which personal data to look for, what to do about it) are not settings. They live in the YAML files in `config/` (see section 7).

---

## 1. General

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_ENVIRONMENT` | `development` | `development`, `test`, `production` | `production` requires a fingerprint key. `test` keeps the normal (not JSON) logs for pytest |
| `GATEWAY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | How much the gateway writes to its log |
| `GATEWAY_HOST` | `127.0.0.1` | an address | Where the gateway listens. `127.0.0.1` means only this computer can connect. Use `0.0.0.0` only behind HTTPS |
| `GATEWAY_PORT` | `8000` | 1 to 65535 | The port to listen on |

## 2. Files and storage

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_POLICY_FILE` | `config/policy.yaml` | a file path | The security policy. Changes made through the API or dashboard are written back here. If it is missing or broken at startup, a strict built-in policy is used |
| `GATEWAY_INJECTION_RULES_FILE` | `config/injection_rules.yaml` | a file path | Prompt injection rules |
| `GATEWAY_PII_ENTITIES_FILE` | `config/pii_entities.yaml` | a file path | Which kinds of personal data to look for, and how sure the detector must be |
| `GATEWAY_SECRET_PATTERNS_FILE` | `config/secret_patterns.yaml` | a file path | Patterns for keys, tokens and passwords |
| `GATEWAY_CONFIDENTIAL_TERMS_FILE` | `config/confidential_terms.yaml` | a file path | Your company's secret project names and "confidential" markings |
| `GATEWAY_DATABASE_URL` | `sqlite:///./data/gateway.db` | a SQLAlchemy URL | The audit log, API keys and policy history. The folder is created if needed. PostgreSQL should work but is not tested |
| `GATEWAY_DASHBOARD_DIR` | `frontend/dist` | a folder, or empty | The built dashboard, served at `/`. Empty turns it off. If the folder has no `index.html`, only the API runs |

## 3. AI providers

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_DEFAULT_PROVIDER` | `mock` | `mock`, `openai`, `anthropic` | Which AI is used when a request doesn't choose one. `mock` is offline and free |
| `GATEWAY_OPENAI_API_KEY` | not set | your key | Turns on the OpenAI provider. Never commit it |
| `GATEWAY_OPENAI_MODEL` | not set | a model name | Required for OpenAI. There is no default, because model names change |
| `GATEWAY_ANTHROPIC_API_KEY` | not set | your key | Turns on the Claude provider. Never commit it |
| `GATEWAY_ANTHROPIC_MODEL` | `claude-opus-5-5` | a model name | Which Claude model to use |
| `GATEWAY_ANTHROPIC_EFFORT` | `medium` | `low`, `medium`, `high`, `xhigh`, `max` | How hard Claude thinks before answering. More effort is slower and costs more |
| `GATEWAY_ANTHROPIC_REFUSAL_FALLBACKS` | `true` | `true`, `false` | Let the Anthropic API retry a refused request on another Claude model |
| `GATEWAY_PROVIDER_TIMEOUT_SECONDS` | `120` | more than 0, up to 600 | How long to wait for one attempt |
| `GATEWAY_PROVIDER_MAX_RETRIES` | `2` | 0 to 5 | Extra attempts after a timeout, rate limit or server error. Login errors and bad requests are never retried |

## 4. API limits

All of these are checked **before** any scanning, so they are cheap.

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | `60` | 1 to 100000 | Requests per API key per minute. More gets 429 with `Retry-After`. Counted in memory, so it resets on restart |
| `GATEWAY_MAX_REQUEST_BYTES` | `1000000` | 1000 to 50000000 | Largest request body. More gets 413, even if the client hides the size |
| `GATEWAY_MAX_REQUEST_CHARS` | `50000` | 1000 to 200000 | All messages and documents of one chat together. Long texts are slow to scan, so this keeps one request from keeping the gateway busy |

## 5. Security behaviour

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_FAIL_MODE` | `closed` | `closed`, `open` | If a detector crashes: `closed` blocks the request (safer), `open` lets it through with a warning. `open` is logged as a warning at startup |
| `GATEWAY_MAX_PROMPT_CHARS` | `20000` | 100 to 1000000 | Longest single text that is scanned. Longer texts are blocked as "text too long" |
| `GATEWAY_STORE_REDACTED_PROMPTS` | `false` | `true`, `false` | Save each prompt in the audit log, with found values hidden. Off by default, because anything the detectors miss would be saved too |
| `GATEWAY_LOG_RETENTION_DAYS` | `30` | 1 to 3650 | Audit events older than this are deleted (at startup, then every hour) |
| `GATEWAY_AUDIT_REQUIRED` | `false` | `true`, `false` | `true`: refuse requests (503) if the audit record can't be saved. `false`: write it to the console log instead and carry on |
| `GATEWAY_OUTPUT_BLOCKED_MESSAGE` | `The answer was withheld by the security gateway because it may contain sensitive information.` | 1 to 500 characters | What the user sees instead of a withheld AI answer |

## 6. Secrets

| Setting | Default | Allowed | What it does |
|---|---|---|---|
| `GATEWAY_FINGERPRINT_KEY` | not set | at least 32 characters | The secret key for fingerprints of found values. **Required in production.** Without it, a random key is made at each start (so fingerprints change after a restart). Make one with `python -c "import secrets; print(secrets.token_hex(32))"` |

---

## 7. The rule files in `config/`

| File | What it holds | Guide |
|---|---|---|
| `policy.yaml` | What to do with each kind of finding, for prompts and for answers | [10-policy-engine.md](10-policy-engine.md) |
| `injection_rules.yaml` | Prompt injection patterns, with categories and confidence | [06-prompt-injection-detection.md](06-prompt-injection-detection.md) |
| `pii_entities.yaml` | Kinds of personal data, confidence limits, phone regions | [07-pii-detection.md](07-pii-detection.md) |
| `secret_patterns.yaml` | Key, token and password patterns | [08-secret-detection.md](08-secret-detection.md) |
| `confidential_terms.yaml` | Your secret project names and markings (the examples should be replaced with your own) | [12-output-scanner.md](12-output-scanner.md) |

The policy can be changed while the gateway runs, through the dashboard or `PUT /v1/policies/active`. It is checked first, and a broken policy changes nothing. The other files are read at startup.
