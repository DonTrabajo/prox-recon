# OPSEC Sanitization Rules

Rules applied to the public core:
- Replace local-only hostnames with placeholders.
- Remove internal usernames and absolute paths.
- Allow only RFC5737 example IP ranges.
- Remove any credentials, tokens, or secrets.

Enforcement lives in `scripts/opsec_scan.py`.