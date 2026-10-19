# Security policy

## Scope

This policy covers the `vulnscan` **tool itself**, not targets you scan with it.

## Reporting a vulnerability in vulnscan

If you find a security issue in `vulnscan.py` or `activescan.py` (e.g. a
weakness in the SSRF canary logic that could be abused by a third party),
please **do not** open a public issue. Instead:

- Email: you@example.com (replace with your contact)
- Include: reproduction steps, affected version, and impact.
- Expected response: within 5 business days.

## Out of scope

- Findings produced by the tool against targets you scanned — those belong
  to the target's owner and whoever authorized the scan.
- Requests to add exploitation features. `vulnscan` deliberately stops at
  detection. See README for recommended exploitation tooling.
