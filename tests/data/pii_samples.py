"""Made-up personal data for testing the PII detector.

Everything here is fake:
  - names and emails are invented, and example.com / example.org are reserved
    test domains
  - 4111 1111 1111 1111 is the standard Visa TEST card number
  - GB82 WEST 1234 5698 7654 32 is the IBAN example from the standard
  - 2345 6789 0124 is a made-up number that passes the Aadhaar check digit
  - ABCPE1234F is a made-up PAN in the right format
  - 555-01xx phone numbers are reserved for fiction in North America

PII_SAMPLES   (text, the entity types that must be found)
NO_PII        text with nothing personal in it
KNOWN_FALSE_POSITIVES  text flagged even though it is not really personal
KNOWN_MISSES  personal data the detector does NOT find
"""

from __future__ import annotations

PII_SAMPLES: list[tuple[str, set[str]]] = [
    ("Contact me at priya.sharma@example.com", {"EMAIL_ADDRESS"}),
    ("Send the invoice to accounts+billing@example.org please", {"EMAIL_ADDRESS"}),
    ("My phone number is +91 98765 43210", {"PHONE_NUMBER"}),
    ("Call (212) 555-0147 after 5pm", {"PHONE_NUMBER"}),
    ("Ring me on +44 20 7946 0958 tomorrow", {"PHONE_NUMBER"}),
    ("My name is Rahul Verma and I live in Mumbai", {"PERSON", "LOCATION"}),
    ("Dr. Anjali Mehta from Bengaluru called about the report", {"PERSON", "LOCATION"}),
    ("Please ask Sarah Johnson to review the contract", {"PERSON"}),
    ("my name is rahul verma", {"PERSON"}),  # lowercase still works here
    ("Card number 4111 1111 1111 1111 exp 12/27", {"CREDIT_CARD"}),
    ("Pay with 4111-1111-1111-1111", {"CREDIT_CARD"}),
    ("Transfer to IBAN GB82 WEST 1234 5698 7654 32", {"IBAN_CODE"}),
    ("Server IP is 192.168.1.20", {"IP_ADDRESS"}),
    ("Connect to 2001:db8::8a2e:370:7334 over IPv6", {"IP_ADDRESS"}),
    ("My SSN is 536-90-4399", {"US_SSN"}),
    ("My Aadhaar number is 2345 6789 0124", {"IN_AADHAAR"}),
    ("PAN card ABCPE1234F", {"IN_PAN"}),
    ("My passport number is J8369854", {"IN_PASSPORT"}),
    (
        "Hi, I'm Neha Kapoor, email neha.k@example.com, phone +91 91234 56780",
        {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"},
    ),
]

NO_PII: list[str] = [
    "Write a function to sort a list in Python.",
    "Use port 8080 on localhost, version 2.10.4",
    "Order #12345678 shipped, error code 0x80070005",
    "ISBN 978-3-16-148410-0",
    "I paid 4500 rupees for the course.",
    "Apple released a new iPhone this year.",
    "def get_user(id): return db.query(User).get(id)",
    "The meeting is at 3pm on Monday.",
    "Card number 1234 5678 9012 3456",  # fails the Luhn check, so not a real card
    "My Aadhaar number is 2345 6789 0125",  # wrong check digit
    "Summarize the quarterly sales report.",
    "The temperature is 25 degrees today.",
    "Please translate 'good morning' into Hindi.",
    "SELECT name, email FROM users WHERE id = 42;",
    "The answer is 42.",
    # The last 12 digits of these UUIDs pass the Aadhaar check digit by chance
    # (found in Phase 8). They must not be reported as Aadhaar numbers.
    "uuid 123e4567-e89b-12d3-a456-426614174000",
    "request_id=9f1c2b7e-0a4d-4e8b-b3c1-234567890124 failed",
    "build-234567890124-final",
]

KNOWN_FALSE_POSITIVES: dict[str, str] = {
    "What is the capital of France?": "places are found even in general knowledge questions",
    "How tall is Mount Everest?": "places are found even in general knowledge questions",
}

# (text, the entity type that SHOULD be found but is not, why)
KNOWN_MISSES: list[tuple[str, str, str]] = [
    (
        "email me at priya dot sharma at example dot com",
        "EMAIL_ADDRESS",
        "spelled-out email address (only the surname is found)",
    ),
    (
        "my number is nine eight seven six five four three two one zero",
        "PHONE_NUMBER",
        "phone number written in words",
    ),
    (
        "I live at 221B Baker Street",
        "LOCATION",
        "street addresses (Presidio has no street address recognizer)",
    ),
    (
        "4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 is my card",
        "CREDIT_CARD",
        "card number with a space between every digit",
    ),
]
