"""Playwright wrapper to confirm real XSS execution via dialogs."""

from __future__ import annotations

from typing import Dict, Optional

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


class BrowserConfirmer:
    """Confirms XSS by listening for JavaScript dialogs while loading a URL."""

    def __init__(self, headless: bool = True, timeout: int = 10) -> None:
        self.headless = headless
        self.timeout = timeout

    def confirm_xss(self, url: str) -> Optional[Dict[str, str | bool]]:
        dialog_capture: Dict[str, str | bool] = {
            "confirmed": False,
            "dialog_type": "",
            "dialog_text": "",
        }

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                def on_dialog(dialog):
                    dialog_capture["confirmed"] = True
                    dialog_capture["dialog_type"] = dialog.type
                    dialog_capture["dialog_text"] = dialog.message
                    dialog.dismiss()

                page.on("dialog", on_dialog)
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                page.wait_for_timeout(self.timeout * 1000)
                context.close()
                browser.close()

        except (PlaywrightTimeoutError, PlaywrightError):
            return None
        except Exception:
            return None

        if dialog_capture.get("confirmed"):
            return dialog_capture
        return None
