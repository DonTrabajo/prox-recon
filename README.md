# DonTrabajoGPT-Core (Public-Safe)

This repository is the **public-safe core** of DonTrabajoGPT. It ships a small,
local recon pipeline (linPEAS parsing + CVE matching) and a deterministic demo
report built from mock inputs.

What is intentionally excluded (OPSEC):
- operational notes and runbooks
- lab-specific workflows, targets, credentials, or flags
- internal KB/mesh tooling, personas, and the TUI
- internal hostnames, absolute host paths, and non-sample IPs
- logs, state files, and local artifacts

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

Verification gates:
- `scripts/preflight.ps1` runs the demo and OPSEC scans locally.
- CI runs the demo plus OPSEC scan on every push/PR.

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
