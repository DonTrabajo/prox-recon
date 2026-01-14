# Security

This public repository excludes operational and lab-specific content by design.

Excluded by design:
- runbooks and init workflows
- internal hostnames and absolute host paths
- non-sample IP addresses
- credentials, tokens, and secrets
- logs, state files, or local artifacts

Safety gates:
- `scripts/opsec_scan.py` enforces OPSEC rules and fails on violations.
- CI runs the OPSEC scan on every push and pull request.