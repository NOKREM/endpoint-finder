# endpoint-finder

Passive API endpoint, service address and AJAX request discovery for any web target.

Give it one URL. It analyses HTML, JavaScript, CSS, source maps, live browser traffic,
Swagger/OpenAPI documents, GraphQL, ArcGIS REST and OGC (WMS/WMTS/WFS/WCS) services, then
reports every endpoint it can prove exists — classified, deduplicated and ranked.

```bash
python main.py https://example.com
```

## What "passive" means here

Only resources the target itself publishes are read:

* the pages and assets a normal browser would already load,
* the standard, publicly advertised metadata files (`robots.txt`, `sitemap.xml`,
  `manifest.json`, `/.well-known/*`),
* schema documents the site itself links to (`swagger.json`, `?f=json`, `GetCapabilities`).

There is **no** path brute-forcing, no parameter fuzzing, no authentication testing and no
requests to the endpoints that get discovered. Guessing conventional documentation paths is
off by default and must be enabled explicitly with `--guess-schemas`.

Use it only against targets you are authorised to assess.

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate on Linux/macOS
pip install -e ".[browser]"
python -m playwright install chromium
```

Playwright is optional. Without it the dynamic capture stage is skipped and the scan
continues with static analysis only.

Extras: `browser` (Playwright), `pdf` (reportlab), `selenium`, `dev` (pytest/black/ruff), `all`.

## Usage

```bash
python main.py https://example.com
python main.py https://example.com --depth 2 --max-pages 50 -f all
python main.py https://example.com --no-render --plain
python main.py https://example.com -H "Authorization: Bearer …" --include "/api/" -f json
endpoint-finder https://example.com          # after pip install
```

### Frequently used options

| Option | Meaning |
| --- | --- |
| `-d, --depth` | Crawl depth, `0` = entry page only (default `1`) |
| `--max-pages`, `--max-assets` | Hard ceilings on the crawl |
| `-c, --concurrency`, `-t, --timeout`, `--retries` | HTTP tuning |
| `--no-render` / `--no-interact` | Disable the headless browser / the click+scroll pass |
| `--render-pages` | How many crawled pages/routes to render (default `3`) |
| `--cdp-url` | Attach to a Chrome you're already running and reuse its session |
| `--verify` | Actively confirm each endpoint with one safe request (opt-in) |
| `--probe/--no-probe` | Fetch schema documents the site references |
| `--guess-schemas` | Additionally try conventional `/swagger.json` style paths |
| `--same-origin`, `--no-subdomains` | Tighten the scope |
| `--host` | Only report endpoints on this domain or its subdomains (repeatable) |
| `--exclude-host` | Skip a domain entirely — nothing fetched, nothing reported (repeatable) |
| `--include`, `--exclude` | Regex allow/deny lists over the whole URL (repeatable) |
| `-f, --format` | `json csv html md sqlite graph pdf all` (repeatable) |
| `-H, --header`, `--cookie`, `--cookie-file`, `-A, --user-agent`, `--proxy`, `-k, --insecure` | Request shaping |
| `--min-confidence`, `--hide-unknown` | Noise control |
| `--plain`, `--limit`, `-v, --verbose`, `-q, --quiet` | Output control |

### `--host` vs `--include`

`--include` is a regex over the **entire URL**, so a third-party tracker that carries
the target address in a query parameter matches it:

```
https://mc.yandex.com/watch/1?page-url=https%3A%2F%2Fwww.example.com%2F   ← matches --include 'example\.com'
```

`--host` compares the **hostname only** and accepts the domain plus its subdomains,
which is almost always what "scan just this site" means:

```bash
endpoint-finder https://www.example.com --host example.com
```

`example.com`, `.example.com`, `*.example.com` and a full URL are all accepted, and
`--exclude-host` takes the same forms. A deny match always beats an allow match.

The two host flags stop at different points on purpose:

| | reported | pages crawled | assets fetched |
| --- | --- | --- | --- |
| `--host` | restricted | restricted | **unrestricted** |
| `--exclude-host` | restricted | restricted | restricted |

`--host` deliberately keeps downloading third-party assets: a bundle served from a CDN
routinely contains the target's own API URLs, and skipping it would lose them.
`--exclude-host` is the explicit "I don't care about this domain at all" switch, so it
also suppresses the request. Combine them to scope tightly and still cut traffic:

```bash
endpoint-finder https://www.example.com --host example.com --exclude-host yandex.com
```

### Targets behind Cloudflare or a WAF

The tool **detects and reports** protection layers; it does not try to get past them.

What it does:

* identifies the vendor (Cloudflare, Akamai, Imperva/Incapsula, Sucuri, AWS WAF,
  DataDome, PerimeterX) from response headers and challenge markers,
* recognises a challenge served with a `200` status, so an interstitial is never
  parsed as if it were the real page,
* **slows itself down automatically** when challenged or rate limited, honouring
  `Retry-After`, and decays the penalty once responses come back clean,
* says so prominently in the summary instead of silently reporting an empty scan,
* reuses a session you established yourself, in both the HTTP client and the browser.

The supported way to scan a protected target you are authorised to test is to hand
the tool a session **you** established. There are three ways to do that, in order of
convenience:

**1. Pass a cookie you already hold.** A single `--cookie`, or a whole exported
session via `--cookie-file` (Netscape `cookies.txt` or a JSON export from a browser
extension). The cookies are installed into both the HTTP client and the browser:

```bash
endpoint-finder https://example.com --cookie cf_clearance=... --concurrency 2
endpoint-finder https://example.com --cookie-file ~/session.txt --concurrency 2
```

**2. Attach to your own Chrome (`--cdp-url`).** Start Chrome with a debugging port,
open the target and clear any challenge yourself in that window, then point the tool
at it. It drives the browser you already cleared and never opens a fresh one:

```bash
chrome --remote-debugging-port=9222        # then open + clear the target in that window
endpoint-finder https://example.com --cdp-url http://127.0.0.1:9222
```

A genuine Chrome frequently passes a challenge that Playwright's bundled Chromium
trips, because the challenge is judging the browser, not solving a puzzle — so this
alone often turns an empty scan into a full one.

*Session sharing.* The attach does more than render: at the start of the scan the
tool reads the cookies from that Chrome and installs them into the **static HTTP
client** too, so the non-browser side of the scan reuses the same human-established
session instead of being challenged on its own. Cookies are kept for the whole
registrable domain, so a session you cleared on `account.example.com` also reaches
the `www` crawl and vice versa. Forms discovered on pages only the real browser could
reach are extracted just like statically fetched ones.

Two caveats worth knowing:

* **Clearance is per Cloudflare zone.** `www.example.com` and `account.example.com`
  can be separately protected. Open *each* subdomain you care about in the attached
  Chrome so its session is available to share.
* A `cf_clearance` cookie only exists once you have solved an *active* challenge. If
  Chrome passed *passively* (no "Just a moment" screen), there is no clearance cookie
  to share — what gets shared then is the ordinary application session, which is
  usually enough.

**3. Turn down the load.** Often the simplest fix — a challenged scan is usually just
too fast:

```bash
EF_RATE_LIMIT_DELAY=1 endpoint-finder https://example.com --concurrency 2 --retries 1
```

Out of scope, deliberately: solving CAPTCHAs or Turnstile, TLS/JA3 fingerprint
spoofing, stealth patches to hide automation, user-agent or proxy rotation. If a
target challenges the scan, that is the target asking for less traffic. Every option
above reuses a human-cleared session; none of them defeats the challenge itself.

### Active verification (`--verify`)

By default the tool never touches the endpoints it finds — it reports what the target
revealed and stops there. `--verify` opts into a single confirmation request per
endpoint so you can see which are actually live (the `status_code` and a `verified`
tag are recorded):

```bash
endpoint-finder https://example.com --verify
```

Two safety rules are absolute: only idempotent verbs are ever sent (`GET`/`HEAD`/
`OPTIONS`), so a discovered `POST`/`PUT`/`PATCH`/`DELETE` is reported but **never
replayed**; and a `HEAD` is preferred over a `GET` so no body is pulled unless the
server rejects it. Verification runs through the same client, so its backoff and
challenge handling still apply.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, at least one endpoint found |
| `1` | Scan failed |
| `2` | Invalid target or options |
| `3` | Scan completed but found nothing |
| `130` | Interrupted |

## Architecture

```
URL ─▶ net/          resilient async HTTP: retries, disk cache, error taxonomy
    ─▶ crawler/      spider (pages) · assets (queue+download) · browser (Playwright) · html · javascript
    ─▶ parser/       urls · jsparser · sourcemap · metadata
    ─▶ discovery/    regex · classifier · api · fetch · xhr · websocket · swagger · graphql · arcgis · geoserver
    ─▶ pipeline.py   orchestration
    ─▶ reporting/    terminal · json · csv · html · markdown · sqlite · graph · pdf
```

Three independent channels feed one deduplicating `EndpointCollector`:

1. **Static** — regex + call-site analysis over HTML, inline scripts, JS, CSS, JSON, XML,
   including URLs assembled by concatenation (`serviceUrl + "/reports?id="`), where the
   base variable is resolved from its assignment in the same file,
   source maps (including `sourcesContent`), `robots.txt`, sitemaps, manifests, cookies,
   response headers (CSP `connect-src` in particular) and web storage.
2. **Dynamic** — Playwright intercepts every request, WebSocket, service worker and console
   error, then scrolls, clicks buttons, opens tabs/accordions/modals to trigger lazy loading.
   Client-side (SPA) routes are recovered from the bundle's router config and the rendered
   DOM, then rendered too, so a single-page app's whole surface is exercised. Can drive a
   Chrome you're already running via `--cdp-url` and share that session with the static side.
3. **Schema** — discovered OpenAPI documents, ArcGIS `?f=json` catalogues and OGC
   `GetCapabilities` responses are parsed and expanded into concrete operations.

### Endpoint classification

`REST` · `GraphQL` · `ArcGIS REST` · `GeoServer` · `Static JSON` · `Tile Server` ·
`Image Service` · `Authentication` · `WebSocket` · `Swagger/OpenAPI` · `SOAP` ·
`Stream/SSE` · `Unknown`

Each endpoint carries its method (observed or inferred), source artefact, evidence snippet,
confidence, parameters and tags.

## Output

Written to `output/<host>.<ext>`:

* **JSON** — full machine readable report (`target`, `scan_time`, `page_title`, `scripts`,
  `requests`, `endpoints[]`, `assets[]`, `errors[]`).
* **CSV** — `URL,METHOD,TYPE,SOURCE,SOURCE_URL,CONFIDENCE,STATUS,CONTENT_TYPE,PARAMS,TAGS`.
* **HTML** — self-contained report with live filtering, sorting and light/dark theme.
* **Markdown**, **PDF** — shareable summaries.
* **SQLite** — every run appended, so scans can be diffed with plain SQL.
* **GraphML** — which JS file references which endpoint, for Gephi/Cytoscape.

## Development

```bash
pytest -q          # 146 tests
ruff check .
black --check .
mypy endpoint_finder
```

Docker:

```bash
docker build -t endpoint-finder .
docker run --rm -v "${PWD}/output:/app/output" endpoint-finder https://example.com
```

## Notes on dependencies

`httpx` covers both sync and async HTTP, so `requests`/`aiohttp` are not required.
`selenium` is available as an optional extra but Playwright is the supported driver.

## License

MIT.
