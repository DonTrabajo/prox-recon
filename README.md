# Prox Recon

**Offline-first reconnaissance core — linPEAS parsing + CVE matching, with CI-enforced OPSEC gates.**

The public core of [Prox Offensive](https://proxoffensive.com)'s recon tooling. It turns
raw linPEAS output into ranked, reviewable findings, and ships a deterministic demo report
built from mock inputs so you can see the output shape without touching a real target.

Runs locally. No cloud calls, no telemetry — sensitive enumeration stays on your machine.

> Part of the Prox Suite. The full operational kit (mesh orchestration, pivot/exploit
> modules, TUI) is kept private by design; this repo is the publishable core.

## What it does
- **linPEAS pipeline** — preprocess → parse → triage raw linPEAS into structured findings
- **CVE matcher** — extract and rank candidate CVEs from parsed JSON
- **Deterministic demo** — `python3 -m tools.demo` builds a sample report from mock inputs

## What's intentionally excluded (OPSEC)
Engineered to be publish-safe. It does not contain operational notes/runbooks,
lab-specific targets/credentials/flags, internal KB/mesh tooling, personas, the TUI,
internal hostnames or non-sample IPs, or logs/state. A CI gate (`scripts/opsec_scan.py`)
blocks these patterns on every push and PR.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m tools.demo
```
Windows (PowerShell): `python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; python -m tools.demo`

## Verification gates
- `scripts/preflight.ps1` runs the demo + OPSEC scan locally.
- CI runs the demo + OPSEC scan on every push/PR.
- `scripts/opsec_testdata/should_fail.txt` deliberately holds banned patterns to prove the
  scanner works; CI excludes that directory so the repo stays publish-safe.

## Layout
`prox_ops/` recon parsing · `tools/` demo entrypoint · `examples/` mock inputs + generated report · `docs/` ARCHITECTURE + SECURITY · `scripts/` preflight + OPSEC scan

## Related
- [ai-redteam-lab](https://github.com/DonTrabajo/ai-redteam-lab) — adversarial test harness for LLMs
- [recon-audit-sample](https://github.com/DonTrabajo/recon-audit-sample) — sample client-facing recon report

## License
MIT — see [LICENSE](LICENSE).
