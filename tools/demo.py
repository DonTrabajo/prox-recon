"""Deterministic demo runner for the public core."""

from __future__ import annotations

import json
from pathlib import Path

from prox_ops.recon import cve_matcher


def _build_report(data: dict, matches: list[dict]) -> str:
    users = data.get("users", [])
    suids = data.get("suid_binaries", [])
    kernel = data.get("kernel", {})
    ips = data.get("ip_addresses", [])
    binaries = data.get("binaries", [])

    lines = [
        "# Prox Recon Demo Report",
        "",
        "## Summary",
        f"- Users: {len(users)}",
        f"- SUID binaries: {len(suids)}",
        f"- Binaries parsed: {len(binaries)}",
        f"- CVE matches: {len(matches)}",
        "",
        "## Kernel",
        f"- {kernel.get('raw', 'unknown')}",
        "",
        "## IPs",
    ]
    for ip in ips:
        lines.append(f"- {ip}")
    lines.append("")

    lines.append("## CVE Matches")
    if matches:
        for hit in matches:
            lines.append(f"- {hit['name']} {hit['version']} ({hit['cve']})")
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    input_path = repo_root / "examples" / "mock_inputs" / "linpeas_parsed.json"
    output_dir = repo_root / "examples" / "output"
    output_path = output_dir / "sample_report.md"

    data = json.loads(input_path.read_text(encoding="utf-8"))
    matches = cve_matcher._match_cves(data.get("binaries", []))
    report = _build_report(data, matches)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")

    rel_path = output_path.relative_to(repo_root)
    print(f"Demo report written to: {rel_path}")
    print("Report title: Prox Recon Demo Report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
