"""FAKE secrets for testing the secret detector.

Why are they built in code instead of written out?
Secret scanners (GitHub push protection, gitleaks and our own repo scan in
tests/security/test_no_secrets_in_repo.py) cannot tell a realistic fake key
from a real one. If this file contained a complete key, GitHub could block
the push, and other people's scanners would raise alarms about our repo.

So each fake secret is built from pieces when the tests run:
  - the prefix is split in two ("AK" + "IA"), so the full format never
    appears in the source
  - the rest is random characters from a FIXED seed, so the values are the
    same on every run and every computer

None of these values work anywhere. They are random characters in the
right shape.
"""

from __future__ import annotations

import base64
import json
import random
import string

# Fixed seed: same fake values every time. This is NOT used for real secrets,
# so a cryptographic generator (which can't be seeded) is not needed here.
_rng = random.Random(7608)  # noqa: S311

LETTERS_DIGITS = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
URL_SAFE = LETTERS_DIGITS + "_-"
BASE64 = LETTERS_DIGITS + "+/"


def _chars(length: int, alphabet: str = LETTERS_DIGITS) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(length))


def _b64url(data: dict[str, object]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# Words that would themselves look like secret assignments in this file
PW = "pass" + "word"

AWS_ACCESS_KEY_ID = "AK" + "IA" + _chars(16, UPPER_DIGITS)
AWS_SECRET_ACCESS_KEY = _chars(40, BASE64)
GITHUB_TOKEN = "gh" + "p_" + _chars(36)
GITHUB_FINE_GRAINED = "github" + "_pat_" + _chars(82, LETTERS_DIGITS + "_")
OPENAI_KEY = (
    "sk-" + "proj-" + _chars(40, URL_SAFE) + "T3Blbk" + "FJ" + _chars(40, URL_SAFE)
)
OPENAI_PROJECT_KEY = "sk-" + "proj-" + _chars(64, URL_SAFE)
ANTHROPIC_KEY = "sk-" + "ant-" + "api03-" + _chars(93, URL_SAFE) + "AA"
GOOGLE_KEY = "AI" + "za" + _chars(35, URL_SAFE)
HUGGINGFACE_TOKEN = "h" + "f_" + _chars(37)
NPM_TOKEN = "np" + "m_" + _chars(36)
SLACK_TOKEN = (
    "xo"
    + "xb-"
    + _chars(12, string.digits)
    + "-"
    + _chars(13, string.digits)
    + "-"
    + _chars(24)
)
SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/"
    + "T"
    + _chars(8, UPPER_DIGITS)
    + "/B"
    + _chars(8, UPPER_DIGITS)
    + "/"
    + _chars(24)
)
STRIPE_LIVE_KEY = "sk" + "_live_" + _chars(24)
STRIPE_TEST_KEY = "sk" + "_test_" + _chars(24)
SENDGRID_KEY = "S" + "G." + _chars(22, URL_SAFE) + "." + _chars(43, URL_SAFE)
AZURE_STORAGE_KEY = _chars(86, BASE64) + "=="
PRIVATE_KEY = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\n"
    + "\n".join(_chars(64, BASE64) for _ in range(6))
    + "\n-----END "
    + "RSA PRIVATE KEY-----"
)
JWT = (
    _b64url({"alg": "HS256", "typ": "JWT"})
    + "."
    + _b64url({"sub": "1234567890", "name": "Test User", "iat": 1700000000})
    + "."
    + _chars(43, URL_SAFE)
)
RANDOM_TOKEN = _chars(32)
FAKE_URL_PASS = "S3cr3t" + "P4ss!"
FAKE_CONFIG_PASS = "Hunter" + "2024!"
FAKE_YAML_PASS = "x9!Kq" + "2@Lm"
FAKE_ENV_PASS = "Pa55w0rd" + "#2026"
FAKE_SENTENCE_PASS = "Tr0ub4" + "dor&3"


# (text, the secret_type that must be found, the exact secret value that must
#  disappear after redaction)
SECRET_SAMPLES: list[tuple[str, str, str]] = [
    (
        f"aws_access_key_id = {AWS_ACCESS_KEY_ID}",
        "AWS_ACCESS_KEY_ID",
        AWS_ACCESS_KEY_ID,
    ),
    (
        f"aws_secret_access_key={AWS_SECRET_ACCESS_KEY}",
        "AWS_SECRET_ACCESS_KEY",
        AWS_SECRET_ACCESS_KEY,
    ),
    (
        f"git remote set-url origin https://{GITHUB_TOKEN}@github.com/acme/app.git",
        "GITHUB_TOKEN",
        GITHUB_TOKEN,
    ),
    (f"GH_TOKEN={GITHUB_FINE_GRAINED}", "GITHUB_TOKEN", GITHUB_FINE_GRAINED),
    (f"OPENAI_API_KEY={OPENAI_KEY}", "OPENAI_API_KEY", OPENAI_KEY),
    (
        f'export OPENAI_API_KEY="{OPENAI_PROJECT_KEY}"',
        "OPENAI_API_KEY",
        OPENAI_PROJECT_KEY,
    ),
    (
        f'client = Anthropic(api_key="{ANTHROPIC_KEY}")',
        "ANTHROPIC_API_KEY",
        ANTHROPIC_KEY,
    ),
    (f"Firebase config apiKey: '{GOOGLE_KEY}'", "GOOGLE_API_KEY", GOOGLE_KEY),
    (f"HF_TOKEN={HUGGINGFACE_TOKEN}", "HUGGINGFACE_TOKEN", HUGGINGFACE_TOKEN),
    (f"//registry.npmjs.org/:_authToken={NPM_TOKEN}", "NPM_TOKEN", NPM_TOKEN),
    (f"our slack bot token is {SLACK_TOKEN}", "SLACK_TOKEN", SLACK_TOKEN),
    (f"Post alerts to {SLACK_WEBHOOK}", "SLACK_WEBHOOK", SLACK_WEBHOOK),
    (f"stripe.api_key = '{STRIPE_LIVE_KEY}'", "STRIPE_SECRET_KEY", STRIPE_LIVE_KEY),
    (f"Test mode key {STRIPE_TEST_KEY}", "STRIPE_TEST_KEY", STRIPE_TEST_KEY),
    (f"SENDGRID_API_KEY={SENDGRID_KEY}", "SENDGRID_API_KEY", SENDGRID_KEY),
    (
        f"DefaultEndpointsProtocol=https;AccountName=acme;AccountKey={AZURE_STORAGE_KEY};EndpointSuffix=core.windows.net",
        "AZURE_STORAGE_KEY",
        AZURE_STORAGE_KEY,
    ),
    (f"Here is my key:\n{PRIVATE_KEY}\nthanks", "PRIVATE_KEY", PRIVATE_KEY),
    (f"Authorization: Bearer {JWT}", "JWT", JWT),
    (
        f"curl -H 'Authorization: Bearer {RANDOM_TOKEN}' https://api.example.com",
        "BEARER_TOKEN",
        RANDOM_TOKEN,
    ),
    (
        f"DATABASE_URL=postgres://admin:{FAKE_URL_PASS}@db.example.com:5432/app",
        "PASSWORD_IN_URL",
        FAKE_URL_PASS,
    ),
    (f"{PW}={FAKE_CONFIG_PASS}", "SECRET_ASSIGNMENT", FAKE_CONFIG_PASS),
    (f'db_{PW}: "{FAKE_YAML_PASS}"', "SECRET_ASSIGNMENT", FAKE_YAML_PASS),
    (f"MYSQL_ROOT_{PW.upper()}={FAKE_ENV_PASS}", "SECRET_ASSIGNMENT", FAKE_ENV_PASS),
    (f"My {PW} is {FAKE_SENTENCE_PASS}.", "PASSWORD", FAKE_SENTENCE_PASS),
    (
        f"My {PW} is `{FAKE_SENTENCE_PASS}` (Markdown code)",
        "PASSWORD",
        FAKE_SENTENCE_PASS,
    ),
    # One or two words between "the" and "password" (found in Phase 12)
    (f"The database {PW} is {FAKE_CONFIG_PASS}", "PASSWORD", FAKE_CONFIG_PASS),
    (f"our wifi {PW} is {FAKE_SENTENCE_PASS}", "PASSWORD", FAKE_SENTENCE_PASS),
    (f"The prod admin {PW} was {FAKE_YAML_PASS}", "PASSWORD", FAKE_YAML_PASS),
    (f"session id {RANDOM_TOKEN} expires soon", "HIGH_ENTROPY_STRING", RANDOM_TOKEN),
]

# Text that talks about secrets, or looks a bit like them, but contains none
NO_SECRETS: list[str] = [
    f"{PW} = os.environ['DB_PASSWORD']",
    f"{PW}: ${{DB_PASSWORD}}",
    "api_key=<your-api-key>",
    f"Set {PW.upper()}=changeme in your .env file",
    f"Enter your {PW}: ********",
    f"The {PW} field must be at least 8 characters long.",
    f"My {PW} is strong.",
    f"The new {PW} is ready.",
    f"The database {PW} is stored in the vault.",
    f"Your old login {PW} was too short.",
    f"The {PW} reset link is in your email.",
    f"if ({PW} == confirmPassword) {{ login() }}",
    f"{PW} = get_secret('db')",
    f"postgres://user:{PW}@localhost:5432/mydb",
    "postgres://localhost:5432/mydb",
    "git commit 3f69f445a0d1004168ad8a86bb490014204898f7",
    "uuid 123e4567-e89b-12d3-a456-426614174000",
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "Use the AKIA prefix to recognise AWS keys.",
    "Bearer tokens are sent in the Authorization header.",
    "Rotate your API keys every 90 days.",
    "sk-this-is-not-a-key",
    "The function verifyPasswordStrength() checks length and symbols.",
    "Download it from https://example.com/files/report-2024-final-version.pdf",
    "ThisIsAVeryLongVariableNameWithoutAnyDigits",
    "token_count = len(tokens)",
    'url = f"postgres://{user}:{db_pass}@{host}/app"',
    'headers = {"api_key": "{API_KEY}"}',
    # Empty values must not "borrow" the next line as their value
    "\n".join(["OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "PORT=8000"]),
    f"db_{PW}:\n  Production2024!",
    # Markdown around a placeholder or a plain word must not hide that it is not a secret
    f"My {PW} is `<value>`.",
    f"My {PW} is **strong**.",
    "Set `api_key` to `${API_KEY}` in your config",
]

# Secrets the detector does NOT find (text, secret value, why)
KNOWN_MISSES: list[tuple[str, str, str]] = [
    (
        "the wifi code is " + "Blue-Sky" + "-42",
        "Blue-Sky-42",
        "a password with no keyword our rules know",
    ),
    (
        "AK IA " + " ".join(AWS_ACCESS_KEY_ID[i : i + 4] for i in range(4, 20, 4)),
        AWS_ACCESS_KEY_ID[4:8],
        "a key broken up with spaces",
    ),
    (
        "mot de passe : " + "Soleil" + "2024!",
        "Soleil2024!",
        "keywords in other languages (French)",
    ),
    (
        "internal token " + "a1b2c3d4" + "e5f6a7b8",
        "a1b2c3d4e5f6a7b8",
        "short custom token with no known format and low randomness",
    ),
]
