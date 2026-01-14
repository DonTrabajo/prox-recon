#!/usr/bin/env python3
"""OPSEC scan for the public core."""

from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import Iterable

RFC5737_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_internal_name = "fe" + "lix"
_hostname_suffix = "." + "local"
_win_users = "C:" + "\\\\" + "Users" + "\\\\"
_mac_users = "/" + "Users" + "/"
_htb_token = "H" + "TB"
_htb_phrase = "Hack" + "The" + "Box"


def _is_rfc5737(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in RFC5737_NETS)


def _redact_line(line: str, start: int, end: int) -> str:
    return f"{line[:start]}[REDACTED]{line[end:]}"


def _iter_text_files(root: Path) -> Iterable[Path]:
    skip_dirs = {".git", ".venv", "venv", "__pycache__"}
    for path in root.rglob("*"):
        if path.is_dir():
            if path.name in skip_dirs:
                continue
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name in {"opsec_scan.py", "opsec_scan.ps1"}:
            continue
        yield path


def scan_file(path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return findings

    lines = raw.splitlines()
    for idx, line in enumerate(lines, start=1):
        # Hostname and username rules
        hostname_pattern = r"\b[\w.-]+" + re.escape(_hostname_suffix) + r"\b"
        for match in re.finditer(hostname_pattern, line, re.IGNORECASE):
            findings.append(
                {
                    "rule": "hostname_local",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )
        for match in re.finditer(_internal_name, line, re.IGNORECASE):
            findings.append(
                {
                    "rule": "internal_username",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )

        # Absolute paths
        for match in re.finditer(re.escape(_win_users), line):
            findings.append(
                {
                    "rule": "absolute_path_windows",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )
        for match in re.finditer(re.escape(_mac_users), line):
            findings.append(
                {
                    "rule": "absolute_path_macos",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )

        # Credentials or lab terms
        for match in re.finditer(r"password\s*[:=]", line, re.IGNORECASE):
            findings.append(
                {
                    "rule": "credential_hint",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )
        htb_pattern = r"\b(" + re.escape(_htb_token) + r"|" + re.escape(_htb_phrase) + r"|" + re.escape(_htb_phrase.replace(\" \", \"\")) + r")\b"
        for match in re.finditer(htb_pattern, line, re.IGNORECASE):
            findings.append(
                {
                    "rule": "lab_platform_term",
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )

        # Secrets
        secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "slack_token": r"xox[baprs]-[A-Za-z0-9-]+",
            "github_token": r"ghp_[A-Za-z0-9]+",
            "openai_key": r"sk-[A-Za-z0-9]+",
            "private_key": r"BEGIN (RSA|OPENSSH|EC) PRIVATE KEY",
        }
        for rule, pattern in secret_patterns.items():
            for match in re.finditer(pattern, line):
                findings.append(
                    {
                        "rule": rule,
                        "file": str(path),
                        "line": str(idx),
                        "snippet": _redact_line(line, match.start(), match.end()),
                    }
                )

        # IP addresses
        for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            ip_text = match.group(0)
            try:
                ip = ipaddress.ip_address(ip_text)
            except ValueError:
                continue
            if _is_rfc5737(ip):
                continue
            if ip.is_private:
                rule = "private_ip"
            else:
                rule = "non_rfc5737_ip"
            findings.append(
                {
                    "rule": rule,
                    "file": str(path),
                    "line": str(idx),
                    "snippet": _redact_line(line, match.start(), match.end()),
                }
            )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="OPSEC scan for public core")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repo root to scan",
    )
    args = parser.parse_args()
    root = Path(args.root)

    all_findings: list[dict[str, str]] = []
    for path in _iter_text_files(root):
        all_findings.extend(scan_file(path))

    if all_findings:
        print("OPSEC scan failed.")
        for finding in all_findings:
            print(
                "FOUND suspicious pattern "
                f"({finding['rule']}) at {finding['file']}:{finding['line']} -> [REDACTED]"
            )
        return 1

    print("OPSEC scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
