"""CLI entry point for The Last Try."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from core.engine import Engine
from core.utils import (
    load_payloads,
    load_user_agents,
    print_branding,
    validate_here_marker,
)

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="the_last_try",
        description=(
            "The Last Try - XSS automation tool that confirms vulnerabilities "
            "via real JavaScript dialogs in a browser."
        ),
    )
    parser.add_argument("target_url", help="Target URL with injection marker HERE exactly once")
    parser.add_argument("-p", "--payload-file", help="Custom payload file (one payload per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--delay", type=float, default=1.0, help="Base delay between requests")
    parser.add_argument(
        "--random-delay",
        type=float,
        default=2.0,
        help="Add random jitter up to this value",
    )
    parser.add_argument(
        "--user-agents",
        dest="user_agents_file",
        help="File with user agents (one per line)",
    )
    parser.add_argument(
        "--no-waf-bypass",
        action="store_true",
        help="Disable WAF detection and bypass module",
    )
    parser.add_argument("-o", "--output", help="Output file (.json or .txt)")
    parser.add_argument(
        "--headless",
        dest="headless",
        action="store_true",
        default=True,
        help="Run browser in headless mode (default: True)",
    )
    parser.add_argument(
        "--no-headless",
        dest="headless",
        action="store_false",
        help="Run browser in headed mode",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Request/page timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print_branding()

    try:
        validate_here_marker(args.target_url)
        payloads = load_payloads(args.payload_file)
        user_agents = load_user_agents(args.user_agents_file)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Input error:[/red] {exc}")
        return 1

    if args.threads < 1:
        console.print("[red]--threads must be >= 1[/red]")
        return 1

    if args.threads > 5:
        console.print("[red]Maximum threads allowed is 5. Please use --threads up to 5 only.[/red]")
        return 1

    if args.timeout < 1:
        console.print("[red]--timeout must be >= 1[/red]")
        return 1

    engine = Engine(
        target_url=args.target_url,
        payloads=payloads,
        user_agents=user_agents,
        threads=args.threads,
        delay=args.delay,
        random_delay=args.random_delay,
        timeout=args.timeout,
        waf_bypass=not args.no_waf_bypass,
        headless=args.headless,
        output_file=args.output,
        verbose=args.verbose,
    )

    try:
        engine.run()
        return 0
    except KeyboardInterrupt:
        console.print("[yellow]Stopped by user.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
