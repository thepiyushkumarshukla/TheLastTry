"""Scanning engine for The Last Try."""

from __future__ import annotations

import random
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from urllib3.util.retry import Retry

from .browser import BrowserConfirmer
from .utils import human_delay, payload_reflected, save_results
from .waf import WAFDetector

console = Console()


class Engine:
    """Main scanner engine implementing request, reflection, and browser verification."""

    def __init__(
        self,
        target_url: str,
        payloads: list[str],
        user_agents: list[str],
        threads: int = 5,
        delay: float = 1.0,
        random_delay: float = 2.0,
        timeout: int = 10,
        waf_bypass: bool = True,
        headless: bool = True,
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.target_url = target_url
        self.payloads = payloads
        self.user_agents = user_agents
        self.threads = threads
        self.delay = delay
        self.random_delay = random_delay
        self.timeout = timeout
        self.waf_bypass = waf_bypass
        self.headless = headless
        self.output_file = output_file
        self.verbose = verbose

        self.results: list[dict] = []
        self.response_log: list[dict] = []
        self.blocked_payloads: set[str] = set()

        self._lock = threading.Lock()
        self._browser_lock = threading.Semaphore(2)
        self._thread_local = threading.local()
        self._stop_event = threading.Event()

        # Reuse object config; browser process is still launched per call in confirmer.
        self._browser_confirmer = BrowserConfirmer(headless=self.headless, timeout=self.timeout)

    def _session(self) -> requests.Session:
        if not hasattr(self._thread_local, "session"):
            retry = Retry(
                total=2,
                connect=2,
                read=2,
                backoff_factor=0.3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry)
            session = requests.Session()
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._thread_local.session = session
        return self._thread_local.session

    def _make_request(self, url: str, user_agent: str) -> Optional[requests.Response]:
        headers = {"User-Agent": user_agent}
        try:
            return self._session().get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            if self.verbose:
                console.print(f"[red][ERROR][/red] Request failed for {url}: {exc}")
            return None

    def _normalize_redirect_depth(self, response: requests.Response) -> bool:
        """Enforce max redirect depth of 3 per project requirements."""
        return len(response.history) <= 3

    def test_payload(self, payload: str, bypass_mode: bool = False) -> Optional[Dict[str, Any]]:
        if self._stop_event.is_set():
            return None

        target = self.target_url.replace("HERE", payload)
        user_agent = random.choice(self.user_agents)

        human_delay(self.delay, self.random_delay, stop_event=self._stop_event)

        if self._stop_event.is_set():
            return None
        response = self._make_request(target, user_agent)

        if response is None:
            return None

        if not self._normalize_redirect_depth(response):
            if self.verbose:
                console.print(f"[red]Too many redirects (>3), skipped[/red] {target[:110]}")
            return None

        response_entry = {
            "payload": payload,
            "url": target,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "bypass_mode": bypass_mode,
        }
        with self._lock:
            self.response_log.append(response_entry)

        if response.status_code in {401, 403, 406, 409, 418, 429, 451, 500, 503}:
            with self._lock:
                self.blocked_payloads.add(payload)
            if self.verbose:
                console.print(
                    f"[red]BLOCKED[/red] {response.status_code} | {'bypass' if bypass_mode else 'normal'} | {payload[:80]}"
                )
            return None

        if not payload_reflected(payload, response.text):
            if self.verbose:
                console.print(f"[dim]Not reflected[/dim] {payload[:80]}")
            return None

        if self._stop_event.is_set():
            return None

        with self._browser_lock:
            if self._stop_event.is_set():
                return None
            dialog = self._browser_confirmer.confirm_xss(target)

        if dialog and dialog.get("confirmed"):
            result = {
                "url": target,
                "payload": payload,
                "dialog_type": dialog.get("dialog_type", ""),
                "dialog_text": dialog.get("dialog_text", ""),
                "timestamp": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "confirmed": True,
            }
            with self._lock:
                self.results.append(result)
            console.print(
                f"[bold green]CONFIRMED[/bold green] {payload[:80]} -> "
                f"{result['dialog_type']}({result['dialog_text']})"
            )
            return result

        if self.verbose:
            console.print(f"[yellow]Reflected, no dialog[/yellow] {payload[:80]}")
        return {"confirmed": False, "payload": payload, "url": target}

    def _render_summary(self) -> None:
        table = Table(title="The Last Try - Confirmed XSS Results")
        table.add_column("Payload", style="cyan", overflow="fold")
        table.add_column("URL", style="magenta", overflow="fold")
        table.add_column("Dialog", style="green")

        if not self.results:
            console.print("[yellow]No confirmed XSS dialogs found.[/yellow]")
            return

        for item in self.results:
            table.add_row(
                item["payload"],
                item["url"],
                f"{item['dialog_type']}: {item['dialog_text']}",
            )

        console.print(table)

    def _signal_handler(self, signum, frame) -> None:  # noqa: ARG002
        if self._stop_event.is_set():
            console.print("\n[red]Forced stop requested. Exiting immediately...[/red]")
            raise KeyboardInterrupt

        console.print("\n[yellow]Interrupt received. Stopping workers (2-3 seconds)...[/yellow]")
        self._stop_event.set()

    def run(self) -> list[dict]:
        original_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Testing payloads", total=len(self.payloads))
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_map = {
                        executor.submit(self.test_payload, payload): payload
                        for payload in self.payloads
                    }

                    for future in as_completed(future_map):
                        try:
                            _ = future.result()
                        except Exception as exc:
                            if self.verbose:
                                console.print(f"[red][worker-error][/red] {exc}")
                        progress.advance(task)

                        if self._stop_event.is_set():
                            for pending in future_map:
                                pending.cancel()
                            executor.shutdown(wait=False, cancel_futures=True)
                            break

            if self.waf_bypass and not self._stop_event.is_set():
                detector = WAFDetector(self)
                if detector.detect() and self.blocked_payloads:
                    console.print(
                        "[yellow]Possible WAF/AV filtering detected. Running extensive bypass attempts...[/yellow]"
                    )

                    def status_cb(msg: str) -> None:
                        if self.verbose:
                            console.print(f"[blue]{msg}[/blue]")

                    estimated_attempts = detector.estimate_total_attempts()
                    with Progress(
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("{task.completed}/{task.total}"),
                        TimeElapsedColumn(),
                        console=console,
                    ) as bypass_progress:
                        bypass_task = bypass_progress.add_task(
                            "Bypass attempts", total=estimated_attempts
                        )

                        def progress_cb() -> None:
                            bypass_progress.advance(bypass_task)

                        bypass_results, bypass_stats = detector.run_bypass(
                            status_cb=status_cb,
                            progress_cb=progress_cb,
                        )

                    console.print(
                        "[cyan]Bypass stats:[/cyan] "
                        f"blocked={bypass_stats['blocked_payloads']} | "
                        f"variants={bypass_stats['total_variants_generated']} | "
                        f"attempts={bypass_stats['total_attempts_run']} | "
                        f"confirmed={bypass_stats['confirmed']}"
                    )

                    for item in bypass_results:
                        if item and item.get("confirmed"):
                            console.print(
                                "[bold green]BYPASS CONFIRMED[/bold green] "
                                f"{item['payload'][:80]}"
                            )

            self._render_summary()

            if self.output_file:
                clean_results = [
                    {
                        "url": item["url"],
                        "payload": item["payload"],
                        "dialog_type": item["dialog_type"],
                        "dialog_text": item["dialog_text"],
                        "timestamp": item["timestamp"],
                    }
                    for item in self.results
                ]
                save_results(self.output_file, clean_results)
                console.print(f"[green]Saved results to {self.output_file}[/green]")

            return self.results

        finally:
            signal.signal(signal.SIGINT, original_handler)
