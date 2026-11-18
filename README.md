# LLM Security Gateway

A security gateway that sits between apps and AI models like OpenAI GPT and Anthropic Claude. It checks prompts and answers for:

- prompt injection attacks
- personal data (PII) like emails and phone numbers
- secrets like API keys and passwords

Then, based on configurable rules, it allows, warns about, hides (redacts) or blocks them.

> **Status:** early development (Phase 5 of 19). The prompt injection detector works on its own; it is not connected to the API yet. A full README comes in Phase 18.

## Quick start (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m uvicorn llm_gateway.main:app --reload
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
