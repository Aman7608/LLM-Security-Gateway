# Development Setup (Windows)

Phase 3 document. Written on 18 November 2026.

This guide shows how the development environment was set up and how to check it. All commands are for **Windows PowerShell**, run from the project folder:

```powershell
cd "C:\Users\amanc\Desktop\LLM Security Guard New"
```

The folder name has spaces, so always put the path in quotes.

---

## 1. Tools on this computer

Checked on 18 November 2026:

| Tool | Version | What we need it for | How to check |
|---|---|---|---|
| Python | 3.12.1 | The backend | `py -3.12 --version` |
| pip (inside the venv) | 26.3 | Installing packages | `.\.venv\Scripts\python.exe -m pip --version` |
| Git | 2.52.0 | Saving versions of the code | `git --version` |
| GitHub CLI | 2.104.0, signed in | Putting the project on GitHub (later, with your OK) | `gh auth status` |
| Docker | 29.4.1 (Compose 5.1.3) | Phase 15. **Docker Desktop is not running yet** | `docker info` |
| Node.js and npm | 24.21.0 and 11.19.0 | Phase 14 (dashboard) | `node --version` |
| VS Code | 1.130.0 | Editor | `code --version` |

### Why Python 3.12 and not 3.13?

This computer also has Python 3.13, and plain `py` starts 3.13 by default. We use **3.12** on purpose. The brief asks for 3.12 or newer, and the PII tools we add in Phase 6 (Presidio and spaCy) have been tested the longest on 3.12. So always create the environment with `py -3.12`.

---

## 2. Virtual environment

A **virtual environment** (venv) is a private Python folder just for this project. Packages installed here do not affect your other projects, and other projects cannot break this one.

```powershell
# Create it (already done, only needed once)
py -3.12 -m venv .venv

# Turn it on (do this in each new terminal)
.\.venv\Scripts\Activate.ps1

# Check it: the path should end with "LLM Security Guard New\.venv"
python -c "import sys; print(sys.prefix)"

# Turn it off
deactivate
```

**Common error:** *"Activate.ps1 cannot be loaded because running scripts is disabled on this system."*
To fix it for your user account only (no admin rights needed):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

If you would rather not change that setting, you can skip activating and call the venv's Python directly: `.\.venv\Scripts\python.exe ...`. Every command in this project's docs works that way.

The `.venv` folder is in `.gitignore`, so it never goes into Git. Anyone can rebuild it from the requirements files.

---

## 3. Packages

We use two files, and every version is pinned with `==`:

| File | What is in it | Who uses it |
|---|---|---|
| `requirements.txt` | Packages the gateway needs to run | The Docker image (Phase 15) |
| `requirements-dev.txt` | Everything in `requirements.txt`, plus test and code-checking tools | Developers |

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
```

`pip check` confirms that no two packages need conflicting versions. Result: **"No broken requirements found."**

**Why pin exact versions?** So the project installs the same way next month as it does today. Without pins, a new release of some package could quietly change behaviour and break a test. For a security tool, that kind of surprise is a problem. With pins, updating a package is a deliberate change that we can test.

**Why not install everything now?** Each package is added in the phase that first uses it. Presidio and its large language model (about 400 MB) come in Phase 6, the AI provider packages in Phase 10, and the database packages in Phase 12. This way we always know why each package is there.

### Installed now

| Package | Version | What it does |
|---|---|---|
| fastapi | 0.163.2 | Web framework for the API |
| uvicorn[standard] | 0.54.0 | Server that runs the API |
| pydantic | 2.14.3 | Checks data shapes and types |
| pydantic-settings | 2.16.3 | Reads settings from environment variables |
| PyYAML | 6.0.3 | Reads policy and rule files |
| httpx | 0.28.1 | Sends HTTP requests. FastAPI's test client also needs it |
| pytest | 9.2.0 | Runs tests |
| pytest-cov | 7.1.0 | Shows how much of the code the tests cover |
| httpx2 | 2.16.2 | Used by FastAPI's test client (added in Phase 4) |
| ruff | 0.17.5 | Checks code style (PEP 8) and formats code |
| mypy | 2.4.1 | Checks type hints |

---

## 4. Git

This project has its **own** Git repository, starting at the project folder:

```powershell
git rev-parse --show-toplevel
# C:/Users/amanc/Desktop/LLM Security Guard New
```

There is also a separate Git repository at `C:\Users\amanc` (your whole home folder). It has nothing to do with this project. Because this project has its own `.git` folder, Git commands here always use the project repository.

### Config files

| File | What it does |
|---|---|
| `.gitignore` | Keeps secrets (`.env`, key files), the venv, caches, local databases and logs out of Git. `.env.example` is allowed, because it only has fake values |
| `.gitattributes` | Saves text files with LF line endings, so they work inside Linux Docker containers. PowerShell scripts keep Windows (CRLF) endings |
| `.editorconfig` | Keeps indentation, encoding and line endings the same in any editor |

**What are LF and CRLF?** They are two ways of marking the end of a line. Windows uses CRLF and Linux uses LF. Docker containers run Linux, and some tools break on CRLF files, so we store LF in Git. This also stops the *"LF will be replaced by CRLF"* warning that appeared in Phases 1 and 2.

### Author name and email

Commits in this repository use:
- Name: `Aman Kumar`
- Email: your GitHub **noreply** address

This is set for this repository only. The noreply address keeps your real email private when the project goes on GitHub.

Your global Git settings still have stray braces (`{Aman`). That does not affect this project. To fix it for all your other repositories:

```powershell
git config --global user.name "Aman Kumar"
git config --global user.email "149958755+Aman7608@users.noreply.github.com"
```

### GitHub

The GitHub CLI is signed in, and its login is stored in the Windows Credential Manager, so you never paste a token anywhere. This repository has **no GitHub link yet**. We only push when you say so.

---

## 5. VS Code

Open the project:

```powershell
code "C:\Users\amanc\Desktop\LLM Security Guard New"
```

`.vscode/settings.json` tells VS Code to:
- use `.venv` as the Python interpreter
- run tests with pytest from the `tests` folder
- format Python with Ruff when you save
- use LF line endings

`.vscode/extensions.json` lists the extensions this project uses. VS Code will ask *"Install recommended extensions?"*. Click **Install**.

---

## 6. Docker

Docker is installed, but **Docker Desktop is not running**. We do not need it until Phase 15. When you are ready:

1. Start **Docker Desktop** from the Start menu and wait for *"Engine running"*.
2. Check it:

```powershell
docker info --format "{{.ServerVersion}}"
docker run --rm hello-world
```

---

## 7. Checking everything at once

```powershell
.\.venv\Scripts\python.exe scripts\check_env.py
```

`scripts/check_env.py` checks:
- the Python version
- that it is running inside this project's venv
- every required package
- that the Git repository starts at this folder
- that `.env` is not tracked by Git
- the GitHub CLI login, Docker and Node.js

It only reads information and never changes anything. If a required check fails, it exits with code 1, so it can also be used in automated checks later.

### Test results (18 November 2026)

| Test | Expected | Result |
|---|---|---|
| Normal run inside the venv | All required checks pass | 16 PASS, 1 WARN (Docker not running), exit code 0 |
| Run with system Python instead of the venv | Venv and package checks fail | 6 FAIL, exit code 1 |
| A `.env` file added to Git on purpose | The `.env` check fails | 1 FAIL, exit code 1. The test file was removed afterwards |
| `ruff check` and `ruff format --check` | No problems | Passed |
| `mypy --strict` | No type errors | Passed |
