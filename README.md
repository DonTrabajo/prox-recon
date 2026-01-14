# DonTrabajoGPT (Public Core)

This is the public-safe core of DonTrabajoGPT. It focuses on local parsing and reporting workflows using mock data, with all operational and lab-specific materials excluded.

What is intentionally excluded (OPSEC):
- operational runbooks and init workflows
- lab-specific notes, targets, credentials, or flags
- internal hostnames and absolute host paths
- non-sample IP addresses
- logs, state files, or local artifacts

Quickstart (Windows, PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m tools.demo
```

Quickstart (macOS/Linux, bash):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m tools.demo
```

Demo command:
```bash
python -m tools.demo
```

Repo structure:
- `prox_ops/` core recon parsing modules
- `tools/` demo entrypoint
- `examples/mock_inputs/` sanitized sample inputs
- `examples/output/` generated demo report
- `docs/` architecture and security notes
- `scripts/` preflight and OPSEC scanning

Docs:
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`