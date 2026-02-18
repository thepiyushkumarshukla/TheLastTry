# The Last Try ⚔️​ [ 最後の試み ]

**The Last Try** is an XSS automation tool focused on one goal: **high-confidence verification**.  
Instead of reporting reflected payloads as vulnerable, it confirms XSS only when a real browser executes JavaScript and raises a dialog (`alert`, `confirm`, `prompt`).

## Features

- ✅ Injection marker workflow using `HERE` in the target URL.
- ✅ Multi-threaded HTTP testing with randomized delay and user-agent rotation.
- ✅ Reflection filter to reduce expensive browser checks.
- ✅ Browser confirmation using Playwright dialog listeners.
- ✅ WAF/AV-style filtering detection and extensive bypass techniques.
- ✅ Startup branding banner with signature “The Last Try” identity.
- ✅ Live bypass progress/status + post-bypass statistics for transparency.
- ✅ Real-time, colorized CLI output with progress tracking.
- ✅ JSON or plain-text report export.

## Why this approach

Most scanners detect reflection and pattern matches, which can create false positives.  
The Last Try verifies browser-side execution by observing JavaScript dialogs on page load.

> Trade-off: XSS payloads that execute only after user interaction may be missed. This is intentional for high-confidence results.

## Project Structure

```text
the_last_try/
├── the_last_try.py
├── core/
│   ├── __init__.py
│   ├── engine.py
│   ├── browser.py
│   ├── waf.py
│   └── utils.py
├── data/
│   ├── payloads.txt
│   ├── bypass_payloads.txt
│   └── user_agents.txt
├── requirements.txt
└── README.md
```

## Installation

1. Use Python 3.9+.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Install browser binaries for Playwright:

```bash
playwright install
```

## Usage

```bash
python the_last_try.py "https://example.com/search?q=HERE"
```

### `HERE` marker requirement

Your target URL must contain `HERE` **exactly once**.

Examples:

- `https://example.com/search?q=HERE`
- `https://example.com/HERE/`
- `https://example.com/index.php?page=HERE&id=5`

## CLI Options

```text
positional arguments:
  target_url            Target URL with injection marker HERE exactly once

optional arguments:
  -p, --payload-file    Custom payload file (one payload per line)
  --threads             Number of concurrent threads (default: 5, max: 5)
  --delay               Base delay between requests in seconds (default: 1.0)
  --random-delay        Add random jitter up to this value (default: 2.0)
  --user-agents         File with user agents (one per line)
  --no-waf-bypass       Disable WAF detection and bypass module
  -o, --output          Output file (.json or .txt)
  --headless            Run browser in headless mode (default)
  --no-headless         Run browser in headed mode
  --timeout             Request/page timeout seconds (default: 10)
  --verbose             Enable detailed logs
```


### Thread safety cap

For stealth and stability, the tool enforces a hard maximum of **5 threads**.
If a higher value is provided, the scan exits with a clear error message.

## Examples

### Basic scan

```bash
python the_last_try.py "https://target.tld/search?q=HERE"
```

### Custom payloads and output

```bash
python the_last_try.py "https://target.tld/?q=HERE" \
  --payload-file custom_payloads.txt \
  --output confirmed.json
```

### Slower, stealthier scan

```bash
python the_last_try.py "https://target.tld/page/HERE" \
  --threads 3 \
  --delay 2 \
  --random-delay 4
```

### Full verbose mode with WAF bypass

```bash
python the_last_try.py "https://target.tld/search?term=HERE" \
  --threads 5 \
  --delay 1.2 \
  --random-delay 2.5 \
  --timeout 12 \
  --verbose \
  --output findings.json
```

## Output interpretation

- **Green (`CONFIRMED`)**: Dialog triggered in browser → confirmed XSS.
- **Yellow**: Reflected payload, but no dialog fired.
- **Red**: Blocked/failure (e.g., WAF/AV rule, request error).

Summary table includes:
- Payload
- Full URL tested
- Dialog type + text

## JSON output format

When saving to `.json`, the report is a list of confirmed findings:

```json
[
  {
    "url": "https://example.com/search?q=<script>alert(1)</script>",
    "payload": "<script>alert(1)</script>",
    "dialog_type": "alert",
    "dialog_text": "1",
    "timestamp": "2025-03-23T10:15:30Z"
  }
]
```

## Branding / Startup UI

When the tool starts, it prints a styled ASCII brand banner with a Japanese/samurai-inspired feel for **The Last Try** so scans have a clear identity in terminal logs and shared screenshots.
It also shows a startup notice to press `Ctrl+C` once or twice and wait 2-3 seconds for graceful stop.

## WAF/AV Detection and Bypass

If enabled, the engine inspects responses for security-filter behavior:

- Status codes (`401`, `403`, `406`, `409`, `418`, `429`, `451`, `500`, `503`)
- Security headers (`cf-ray`, `x-sucuri-*`, `x-mod-security`, etc.)
- Block-page strings (`access denied`, `threat detected`, `captcha`, etc.)

When likely filtering is detected, blocked payloads are retested with **multiple bypass methods**:

1. **Case mutation**
   - Example: `<script>` → `<sCrIpT>`
2. **Encoding mutation**
   - URL-encoded, double URL-encoded, HTML entity encoded
3. **Fragmentation/signature breaking**
   - Script token split (`<scr<script>ipt>`) and comment/junk appends
4. **Alternative handlers/functions**
   - `onerror` → `onload`/`onmouseover`, `alert` → `confirm`/`prompt`
5. **Prefix/suffix/context breakers**
   - Prefixing with `'`, `"`, `-->`, `</title>`, etc.
6. **Dedicated bypass library**
   - Large fallback payload set in `data/bypass_payloads.txt`

### What bypass means in practice

A bypass means changing the payload shape/signature so filtering engines miss it while the browser still executes JavaScript.  
The scanner uses this workflow automatically:

- Detect probable filtering.
- Collect blocked payloads.
- Generate transformed variants.
- Re-test each variant with live progress updates.
- Print bypass stats (blocked payloads, variants generated, attempts run, confirmed).
- Report only variants that still trigger real dialogs in browser.

## Directly push this project to your GitHub repo

From the repository root:

```bash
# 1) Create your own repository on GitHub first, then:
git remote add origin https://github.com/<your-username>/<your-repo>.git

# 2) Push current branch (replace branch name if needed)
git push -u origin work
```

If `origin` already exists and you want to replace it:

```bash
git remote remove origin
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin work
```

Using SSH instead of HTTPS:

```bash
git remote add origin git@github.com:<your-username>/<your-repo>.git
git push -u origin work
```

## Performance notes

- HTTP testing is multithreaded.
- Browser checks are limited with a semaphore to avoid overloading the host.
- Reflection filtering now checks decoded + HTML-unescaped forms for better accuracy without over-launching browsers.
- Duplicate payloads are removed while preserving order to reduce unnecessary requests and improve scan throughput safely.
- Redirect handling is normalized to skip chains longer than 3 redirects, improving reliability and matching intended behavior.

## Error handling and stopping

- Request, timeout, and Playwright errors are handled per payload and do not crash the whole run.
- Press `Ctrl+C` to stop gracefully; worker tasks are signaled immediately and pending futures are canceled for faster exits (typically within 2-3 seconds depending on in-flight browser/request operations).
- Pressing `Ctrl+C` again triggers a forced stop path if needed.

## Limitations

- Requires Playwright browser installation.
- Focused on dialog-based proof, so non-dialog XSS paths can be missed.
- Headed mode can be noisy on desktop environments.

## Legal notice

Use this tool only on systems you are authorized to test.
