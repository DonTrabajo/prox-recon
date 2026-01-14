# Architecture

This public core provides a minimal recon pipeline on sanitized sample data.

Components:
- `prox_ops/recon/linpeas_preprocessor.py`: extracts users, SUID binaries, kernel data, IPs, and binaries
- `prox_ops/recon/linpeas_parser.py`: prints a summary of parsed JSON
- `prox_ops/recon/linpeas_summarizer.py`: renders a text summary of findings
- `prox_ops/recon/cve_matcher.py`: demo CVE matcher for common binaries
- `tools/demo.py`: deterministic demo runner using mock inputs

Data flow:
1) Demo loads `examples/mock_inputs/linpeas_parsed.json`
2) CVE matcher runs against the mock binaries
3) A sample report is written to `examples/output/sample_report.md`