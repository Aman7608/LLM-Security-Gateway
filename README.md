# LLM Security Gateway

A security gateway that sits between apps and AI models like OpenAI GPT and Anthropic Claude. It checks prompts and answers for:

- prompt injection attacks
- personal data (PII) like emails and phone numbers
- secrets like API keys and passwords

Then, based on configurable rules, it allows, warns about, hides (redacts) or blocks them.

> **Status:** early development (Phase 12 of 19). The detectors, DLP engine and policy engine work, the gateway can talk to a free offline mock AI, OpenAI or Anthropic Claude, AI answers are checked for leaks before anyone sees them, and every decision is kept in a privacy-safe audit log. It is not connected to the web API yet. A full README comes in Phase 18.

## Quick start (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m uvicorn llm_gateway.main:app --reload

# Send a prompt through the gateway's checks to the free mock AI
.\.venv\Scripts\python.exe scripts\try_provider.py --protect "Email priya@example.com the report"
```

Then open http://127.0.0.1:8000/health or the API docs at http://127.0.0.1:8000/docs.

## Documents

| Document | What it covers |
|---|---|
| [docs/01-project-requirements.md](docs/01-project-requirements.md) | What the gateway must do |
| [docs/02-system-architecture.md](docs/02-system-architecture.md) | How it is designed |
| [docs/03-threat-model.md](docs/03-threat-model.md) | Attacks and defences |
| [docs/04-development-setup.md](docs/04-development-setup.md) | Setting up the tools |
| [docs/05-project-structure.md](docs/05-project-structure.md) | Folders, files and settings |
| [docs/06-prompt-injection-detection.md](docs/06-prompt-injection-detection.md) | How prompt injection is detected, test results and limits |
| [docs/07-pii-detection.md](docs/07-pii-detection.md) | How personal data is found and hidden, test results and limits |
| [docs/08-secret-detection.md](docs/08-secret-detection.md) | How API keys, tokens and passwords are found, test results and limits |
| [docs/09-dlp-engine.md](docs/09-dlp-engine.md) | How the detectors are joined, how decisions are made, the default policy |
| [docs/10-policy-engine.md](docs/10-policy-engine.md) | Risk levels, combined signals, policy checks, versions and safe reloading |
| [docs/11-llm-providers.md](docs/11-llm-providers.md) | The mock, OpenAI and Claude providers, retries, timeouts and key safety |
| [docs/12-output-scanner.md](docs/12-output-scanner.md) | Checking AI answers: confidential terms, system prompt leaks and the output guard |
| [docs/13-audit-logging.md](docs/13-audit-logging.md) | The audit log: what is saved (and never saved), fingerprints, the database and policy history |
