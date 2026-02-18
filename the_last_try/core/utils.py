"""Utility helpers for The Last Try."""

from __future__ import annotations

import json
import random
import time
from html import unescape
from pathlib import Path
from typing import List, Sequence
from urllib.parse import unquote

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_branding() -> None:
    """Render startup branding banner for The Last Try."""
    logo = Text(
        """
████████╗██╗  ██╗███████╗    ██╗      █████╗ ███████╗████████╗
╚══██╔══╝██║  ██║██╔════╝    ██║     ██╔══██╗██╔════╝╚══██╔══╝
   ██║   ███████║█████╗      ██║     ███████║███████╗   ██║
   ██║   ██╔══██║██╔══╝      ██║     ██╔══██║╚════██║   ██║
   ██║   ██║  ██║███████╗    ███████╗██║  ██║███████║   ██║
   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝

████████╗██████╗ ██╗   ██╗
╚══██╔══╝██╔══██╗╚██╗ ██╔╝
   ██║   ██████╔╝ ╚████╔╝
   ██║   ██╔══██╗  ╚██╔╝
   ██║   ██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝   ╚═╝
        """.strip("\n"),
        style="bold cyan",
    )

    subtitle = (
        "[bold white]High-confidence XSS verification via real browser dialogs[/bold white]\n"
        "[green]Brand:[/green] The Last Try  [yellow]Mode:[/yellow] Reflection + Browser + Smart Bypass"
    )

    console.print(Panel.fit(f"{logo}\n\n{subtitle}", border_style="bright_magenta"))


def _load_lines(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    lines: List[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_payloads(filepath: str | None = None) -> List[str]:
    """Load payloads from custom file or built-in list."""
    data_path = Path(__file__).resolve().parent.parent / "data" / "payloads.txt"
    path = Path(filepath) if filepath else data_path
    payloads = _load_lines(path)
    if not payloads:
        raise ValueError(f"No payloads found in file: {path}")

    # Preserve order while removing duplicates to improve speed and consistency.
    deduped = list(dict.fromkeys(payloads))
    return deduped


def load_user_agents(filepath: str | None = None) -> List[str]:
    """Load user agents from custom file or built-in list."""
    data_path = Path(__file__).resolve().parent.parent / "data" / "user_agents.txt"
    path = Path(filepath) if filepath else data_path
    user_agents = _load_lines(path)
    if not user_agents:
        raise ValueError(f"No user agents found in file: {path}")
    return user_agents


def human_delay(base: float, jitter: float) -> None:
    """Sleep with base delay and random jitter."""
    jitter_value = random.uniform(0.0, max(jitter, 0.0))
    time.sleep(max(base, 0.0) + jitter_value)


def _reflection_candidates(payload: str) -> set[str]:
    return {
        payload,
        unquote(payload),
        unquote(unquote(payload)),
        unescape(payload),
        unescape(unquote(payload)),
    }


def payload_reflected(payload: str, html: str) -> bool:
    """Check if payload or reasonably decoded/escaped variants are reflected."""
    if not html:
        return False

    body_forms = {
        html,
        unescape(html),
        unquote(html),
    }

    for candidate in _reflection_candidates(payload):
        if not candidate:
            continue
        for body in body_forms:
            if candidate in body:
                return True
    return False


def save_results(output_file: str, results: Sequence[dict]) -> None:
    """Save confirmed results as JSON or plain text based on extension."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix.lower() == ".json":
        output_path.write_text(json.dumps(list(results), indent=2), encoding="utf-8")
        return

    lines = []
    for item in results:
        lines.append(
            " | ".join(
                [
                    f"url={item.get('url', '')}",
                    f"payload={item.get('payload', '')}",
                    f"dialog_type={item.get('dialog_type', '')}",
                    f"dialog_text={item.get('dialog_text', '')}",
                    f"timestamp={item.get('timestamp', '')}",
                ]
            )
        )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_here_marker(target_url: str) -> None:
    count = target_url.count("HERE")
    if count != 1:
        raise ValueError(
            "Target URL must contain marker 'HERE' exactly once. "
            f"Found {count} occurrence(s)."
        )
