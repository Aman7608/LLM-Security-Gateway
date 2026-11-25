# Security Policy

This is a security tool, so security problems in it matter twice: once for the gateway itself, and once for the apps that trust it.

## What counts as a security problem

- a way to get **past the gateway's checks that is not already listed** in [docs/red-team-report.md](docs/red-team-report.md) or the "known misses" sections of the guides
- a way to make the gateway **leak a value it found** (in a reply, a log, the audit database or the dashboard)
- a way to use the API **without a valid key**, or to use an admin route with a client key
- anything that makes the gateway **crash, hang or use lots of memory** with a small request
- a **real secret** committed to this repository (all secrets in the tests are fake and built at runtime)

Known bypasses that are already in the red team report are not new reports, but new ways around them are welcome.

## How to report one

Please **don't open a public issue** with the details, because that tells everyone at once.

Instead, use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainer can see it.

Please include:
- what you sent (a prompt, a request, or the steps to repeat it)
- what happened, and what you expected
- the version or commit you used

Don't include real personal data or real keys in a report. Made-up values work just as well.

## What to expect

This is a one-person learning project, so there is no paid support. I will try to:
- reply within **7 days**
- fix confirmed problems, or add them to the known limits, and credit you if you want

## Supported versions

Only the latest version on the `main` branch gets fixes.

## Using it safely

The gateway is **one layer of protection**. Read the [limitations](README.md#limitations) before relying on it:
- don't put it on a network without HTTPS in front of it
- keep `GATEWAY_FAIL_MODE=closed`
- set your own `GATEWAY_FINGERPRINT_KEY`
- keep API keys in a password manager, never in code
