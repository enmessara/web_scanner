# webscanner.sh

A bash-based **recon and attack-surface mapper** for bug bounty triage. It crawls a
target, maps every reachable in-scope endpoint, and flags *candidates* for manual
testing against common OWASP categories — without ever sending an exploit payload.

## Why "candidates" and not "vulnerabilities"

This tool is intentionally **passive only**. It reads what the server actually sends
back (response headers, cookies, HTML, linked JS source, `robots.txt`) and never:

- injects XSS/SQLi strings
- fires requests at SSRF targets
- swaps object IDs to try to read another user's data
- replays requests with stripped/forged auth tokens

Confirming any of the categories below is a manual step — this tool exists to make
that manual step fast by handing you a prioritized shortlist instead of a blank page.

| Category | What this tool gives you |
|---|---|
| Access Control / IDOR / BOLA | Endpoints with numeric/UUID params or path-based IDs, and pages that redirected to a login page |
| Injection | Full list of discovered forms (method, action, inputs) to fuzz manually |
| SSRF | Params named like `url=`, `redirect=`, `callback=`, `webhook=` |
| Insecure Design | Forms with no CSRF-token-looking field; sensitive paths (`/admin`, `/api/internal`, …) |
| Cryptographic Failures | Missing HSTS, missing cookie `Secure`/`HttpOnly`/`SameSite`, mixed HTTP content on HTTPS pages |

The next step for anything flagged here is a proper intercepting proxy
(**Burp Suite** / **OWASP ZAP**) and manual testing, within the scope and rate
limits of the program you're testing under.

## Features

- Proper crawler: BFS traversal with configurable depth/page limits, same-domain
  (optionally subdomain-inclusive) scope enforcement
- Correct relative-URL resolution (`../`, `./`), not string concatenation
- Query-string-aware deduplication with a cap on variants per path, so
  `?id=1..100000` doesn't explode the crawl while still tracking distinct IDs
- Full input validation on every numeric flag
- `robots.txt` / `sitemap.xml` seeding
- Common sensitive-path existence check (`.git/HEAD`, `.env`, `/admin`, etc. —
  existence only, nothing is exploited if found)
- Passive JS-file mining for API-looking endpoint strings
- Security header, cookie-flag, and mixed-content auditing
- Form discovery with lightweight CSRF-field detection
- Rough triage score + risk label to prioritize what to look at first
- Text, JSON, and styled dark-mode HTML reports

## Usage

```bash
chmod +x webscanner.sh
./webscanner.sh -u https://example.com -p 100 -d 4 -s --json --html
```

| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Target URL | — |
| `-p, --max-pages` | Max pages to crawl | 50 |
| `-d, --max-depth` | Max crawl depth | 3 |
| `-t, --delay` | Delay between requests (seconds) | 1 |
| `-q, --max-query-variants` | Max query-string variants per path | 5 |
| `-s, --subdomains` | Include subdomains in scope | off |
| `-o, --output-dir` | Output directory | `scan_<host>_<timestamp>` |
| `--json` | Also write `report.json` | off |
| `--html` | Also write `report.html` | off |
| `--quiet` | Suppress live per-page console output | off |

Omitting `-u` falls back to interactive prompts.

## Output

Every run produces a directory containing:

```
endpoints.txt                 every in-scope URL crawled, with status code
external_links.txt            off-scope links found (not crawled)
idor_bola_candidates.txt      access-control test candidates
ssrf_param_candidates.txt     SSRF test candidates
sensitive_paths.txt           admin/api/auth paths, login-redirects
headers_report.txt            missing security headers, per URL
cookie_report.txt             cookie flag issues, per URL
mixed_content_report.txt      http:// resources on https:// pages
redirect_report.txt           requested URL -> final URL
forms_report.txt              every form's method/action/inputs
js_discovered_endpoints.txt   API-looking paths found inside .js files
common_paths_found.txt        hits from the built-in sensitive-path wordlist
summary_report.txt            everything above, combined
report.json                   machine-readable version (if --json)
report.html                   dark-mode styled report (if --html)
```

## Known limitations

- CSRF-field detection is page-level, not per-form — a page with one form that
  has a token and one that doesn't may under-flag the second form.
- JS endpoint mining is a regex over string literals; it won't catch
  dynamically-constructed URLs (`base + "/" + id`).
- Headers/cookies are only checked on the HTML pages actually crawled, not on
  every asset.
- This is a **recon** tool. Treat every file here as a prioritized list for
  manual verification, not a confirmed-findings report.

## Responsible use

Only run this against targets you are explicitly authorized to test (a program's
published scope, or infrastructure you own). Respect program rate limits —
`--delay` and `--max-pages` exist for this reason.

## License

MIT — do whatever you like with it, no warranty.
