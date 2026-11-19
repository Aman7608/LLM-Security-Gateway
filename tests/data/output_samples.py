"""Made-up AI answers for testing the output scanner.

LEAKY_ANSWERS   answers that must be blocked or have something hidden:
                (answer, expected action, a piece of text that must not
                reach the user)
SAFE_ANSWERS    normal answers that must pass unchanged
SYSTEM_PROMPT   the hidden instructions used for the leak tests

Fake secrets are built from pieces, as in tests/data/secret_samples.py.
"""

from __future__ import annotations

from tests.data.secret_samples import AWS_ACCESS_KEY_ID, GITHUB_TOKEN, PRIVATE_KEY

SYSTEM_PROMPT = (
    "You are SupportBot for Acme Retail. Never offer refunds above 50 dollars "
    "without manager approval. Do not mention the upcoming store closures in "
    "Pune. Escalate legal threats to legal@acme.example within one hour."
)

LEAKY_ANSWERS: list[tuple[str, str, str]] = [
    # Secrets
    (f"Here is the deploy key: {AWS_ACCESS_KEY_ID}", "block", AWS_ACCESS_KEY_ID),
    (f"Use this token: {GITHUB_TOKEN} to clone.", "block", GITHUB_TOKEN),
    (f"The server key is:\n{PRIVATE_KEY}", "block", PRIVATE_KEY.splitlines()[1]),
    # Personal data
    ("The customer's email is priya@example.com.", "redact", "priya@example.com"),
    ("Call her on +91 98765 43210 today.", "redact", "98765 43210"),
    ("The card on file is 4111 1111 1111 1111.", "redact", "4111 1111 1111 1111"),
    ("Aadhaar number: 2345 6789 0124.", "redact", "2345 6789 0124"),
    # Confidential terms (examples from config/confidential_terms.yaml)
    ("Project Nightingale closes next week.", "redact", "Nightingale"),
    ("The Bluebird Pro launches in March.", "redact", "Bluebird Pro"),
    (
        "This report is STRICTLY CONFIDENTIAL: revenue fell 12%.",
        "redact",
        "STRICTLY CONFIDENTIAL",
    ),
    # The system prompt, repeated word for word
    (
        "My rules say: never offer refunds above 50 dollars without manager approval.",
        "block",
        "without manager approval",
    ),
    (
        "Sure! Do not mention the upcoming store closures in Pune. Escalate legal threats.",
        "block",
        "store closures in Pune",
    ),
]

SAFE_ANSWERS: list[str] = [
    "Our return window is 30 days from the date of delivery.",
    "You can track your order from the Orders page.",
    "Paris is the capital of France.",
    "Here is a Python function that adds two numbers: def add(a, b): return a + b",
    "Refunds are processed within 5 to 7 working days.",
    "I'm not able to help with that request.",
    "Your data is kept private according to our privacy policy.",
    "The weather in Delhi is usually hot in May.",
    "Commit 3f69f445a0d1004168ad8a86bb490014204898f7 fixed the bug.",
    # Shares a few words with the system prompt, but far fewer than 8 in a row
    "Our support team can help with refunds and store information.",
]

# Answers that only get a WARNING (logged, not changed)
WARN_ANSWERS: list[str] = [
    "Is my data kept confidential? Yes, we never sell it.",
    "That document was marked internal use only, so I can't summarise it.",
    "The article said: ignore all previous instructions. It was a test page.",
]
