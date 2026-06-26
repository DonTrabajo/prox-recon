"""Optional LLM triage layer for Prox Recon.

Takes parsed linPEAS findings and asks an LLM to rank likely privilege-escalation
paths. This layer is opt-in and endpoint-agnostic: point OPENAI_BASE_URL at a local
runtime (e.g. Ollama's OpenAI-compatible endpoint) to keep everything on your machine,
or at a hosted API if you accept sending findings off-box. Enumeration itself always
stays local — this only runs when you explicitly enable it and configure an endpoint.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from openai import OpenAI
from rich.console import Console
from rich.panel import Panel

# Load .env before reading the key/endpoint.
load_dotenv()
console = Console()


def _get_client() -> OpenAI | None:
    """Lazily create an OpenAI-compatible client; return None if unconfigured."""
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL")
    if not api_key:
        console.print("[yellow]OPENAI_API_KEY not set; skipping LLM triage.[/yellow]")
        return None
    try:
        return OpenAI(api_key=api_key, base_url=base_url)
    except Exception as exc:  # noqa: BLE001 - surface any client init failure
        console.print(f"[red]Failed to initialize LLM client: {exc}[/red]")
        return None


def format_prompt(parsed_data: dict) -> str:
    """Build a tight triage prompt from parsed linPEAS findings."""
    users = parsed_data.get("users", [])
    suids = parsed_data.get("suid_binaries", [])
    kernel = parsed_data.get("kernel", {})
    ips = parsed_data.get("ip_addresses", [])
    binaries = parsed_data.get("binaries", [])

    return f"""You are a privilege-escalation triage assistant for a Linux host.
Given the enumeration below, identify the most promising escalation or exploitation
paths. Be concise and concrete: name the specific check, technique, or binary to
investigate first, and why.

Users: {users}
SUID binaries: {suids}
Kernel: {kernel}
IPs: {ips}
Binaries: {binaries}

Rank the top paths to investigate first."""


def run_gpt_analysis(parsed_data: dict) -> str | None:
    """Run LLM triage on parsed findings. Returns the summary text, or None if skipped."""
    client = _get_client()
    if not client:
        return None

    try:
        response = client.chat.completions.create(
            model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "You are a red team operations assistant."},
                {"role": "user", "content": format_prompt(parsed_data)},
            ],
            temperature=0.7,
            max_tokens=700,
        )
        output = (response.choices[0].message.content or "").strip()
        console.print(Panel(output, title="LLM Triage", border_style="bright_blue"))
        return output
    except Exception as exc:  # noqa: BLE001 - network/model errors are non-fatal
        console.print(f"[red]LLM request failed: {exc}[/red]")
        return None
