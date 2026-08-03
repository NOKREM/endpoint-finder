"""Headless browser capture: network interception plus scripted interaction.

Playwright is an optional dependency. When it is unavailable the capture simply
reports ``available=False`` and the pipeline continues with static analysis only.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from endpoint_finder.config import Settings
from endpoint_finder.logging_setup import get_logger

logger = get_logger(__name__)

#: Resource types that always represent an API call rather than a page asset.
API_RESOURCE_TYPES: frozenset[str] = frozenset({"xhr", "fetch", "eventsource", "websocket"})

#: Selectors clicked to trigger lazy loaded content.
INTERACTION_SELECTORS: tuple[str, ...] = (
    "button:not([type=submit]):not([disabled])",
    "[role='tab']",
    "[role='button']",
    "[data-toggle]",
    "[data-bs-toggle]",
    "[aria-expanded='false']",
    "summary",
    ".accordion-button",
    ".accordion-header",
    ".nav-link",
    ".tab",
    ".tabs a",
    ".load-more",
    "[data-modal]",
    "[data-target]",
)

#: Selectors dismissed before interacting so overlays do not swallow clicks.
DISMISS_SELECTORS: tuple[str, ...] = (
    "#onetrust-accept-btn-handler",
    ".cc-dismiss",
    "[aria-label='close']",
    "[data-dismiss='modal']",
)


@dataclass(slots=True)
class NetworkRequest:
    """A request observed by the browser.

    Attributes:
        url: Request URL.
        method: HTTP verb.
        resource_type: Playwright resource type (``xhr``, ``fetch``, ``script`` ...).
        status: Response status, ``None`` when the request failed.
        content_type: Response content type.
        post_keys: Field names found in the request body, when parseable.
        initiator: The page that triggered the request.
        failure: Failure text for requests that never completed.
    """

    url: str
    method: str = "GET"
    resource_type: str = "other"
    status: int | None = None
    content_type: str = ""
    post_keys: list[str] = field(default_factory=list)
    initiator: str = ""
    failure: str = ""


@dataclass(slots=True)
class BrowserCapture:
    """Everything the headless browser observed.

    Attributes:
        available: Whether Playwright ran at all.
        error: Reason the capture was skipped or failed.
        title: Document title after the page settled.
        html: Rendered DOM snapshot.
        final_url: URL after client side redirects.
        requests: Every intercepted network request.
        websockets: WebSocket URLs the page connected to.
        cookies: Cookies set on the target.
        console_errors: JavaScript errors and console error messages.
        service_workers: Service worker script URLs.
        storage_urls: URLs found in local/session storage values.
        interactions: Number of successful synthetic interactions.
    """

    available: bool = False
    error: str | None = None
    title: str = ""
    html: str = ""
    final_url: str = ""
    requests: list[NetworkRequest] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    console_errors: list[str] = field(default_factory=list)
    service_workers: list[str] = field(default_factory=list)
    storage_urls: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    interactions: int = 0

    @property
    def api_requests(self) -> list[NetworkRequest]:
        """Only the requests that look like API traffic."""
        return [
            request
            for request in self.requests
            if request.resource_type in API_RESOURCE_TYPES
            or "json" in request.content_type
            or request.method not in {"GET", "HEAD"}
        ]


def playwright_available() -> bool:
    """Whether the optional Playwright dependency is importable.

    Returns:
        ``True`` when ``playwright.async_api`` can be imported.
    """
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False
    return True


async def capture(url: str, settings: Settings) -> BrowserCapture:
    """Render a single page and record every request it makes.

    The function never raises: browser problems are reported through
    :attr:`BrowserCapture.error` so the scan can continue.

    Args:
        url: Page to render.
        settings: Active settings (timeouts, interaction budget, proxy ...).

    Returns:
        The capture, with ``available=False`` when Playwright could not run.
    """
    captures = await capture_many([url], settings)
    return captures[0] if captures else BrowserCapture(error="no page rendered")


async def capture_many(urls: list[str], settings: Settings) -> list[BrowserCapture]:
    """Render several pages in one browser session.

    XHR traffic is per page: the endpoints a ski-report page requests are simply
    not requested by the home page. Rendering only the entry point therefore
    misses everything the rest of the application does, which is why this takes a
    list. One browser and one context are reused across pages so the extra cost
    is roughly the page load itself.

    Args:
        urls: Pages to render, in priority order.
        settings: Active settings.

    Returns:
        One capture per URL. On a launch failure a single failed capture is
        returned describing the problem.
    """
    if not settings.render or not urls:
        return [BrowserCapture(error="rendering disabled")] if not settings.render else []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("playwright not installed - skipping dynamic capture")
        return [
            BrowserCapture(
                error="playwright not installed (pip install 'endpoint-finder[browser]')"
            )
        ]

    results: list[BrowserCapture] = []
    try:
        async with async_playwright() as driver:
            if settings.cdp_url:
                browser, context, owns_browser = await _attach_over_cdp(driver, settings)
            else:
                browser, context, owns_browser = await _launch_browser(driver, settings)
                await _seed_cookies(context, urls[0], settings)
            try:
                context.set_default_timeout(settings.browser_timeout * 1000)
                for url in urls:
                    results.append(await _capture_page(context, url, settings))
            finally:
                # A browser the user is running is left untouched; only one we
                # started ourselves gets closed.
                if owns_browser:
                    await browser.close()
    except Exception as exc:  # noqa: BLE001 - the browser must never break a scan
        logger.warning("browser capture failed: %s", exc)
        results.append(BrowserCapture(error=f"{type(exc).__name__}: {exc}"))
    return results


async def harvest_cdp_cookies(settings: Settings, host: str) -> list[Any]:
    """Read the session cookies from a Chrome attached over CDP.

    When the user cleared a challenge in their own Chrome, the clearance cookie
    lives only in that browser. Handing it to the static HTTP client too lets the
    non-browser side of the scan reuse the same human-established session instead
    of being challenged on its own. Nothing is created or bypassed here - the
    cookies are simply read from the browser the user is running.

    Args:
        settings: Active settings carrying ``cdp_url``.
        host: Target hostname, used to keep only relevant cookies.

    Returns:
        A list of :class:`~endpoint_finder.cookies.CookieRecord`, empty on failure.
    """
    if not settings.cdp_url:
        return []
    try:
        from playwright.async_api import async_playwright

        from endpoint_finder.cookies import CookieRecord
        from endpoint_finder.parser.urls import registered_domain
    except ImportError:
        return []

    # Keep cookies for the whole registrable domain, not just the exact host: a
    # clearance cookie the user obtained for account.example.com must reach the
    # static client too, and that host is a sibling of the www target.
    base = registered_domain(host)

    records: list[Any] = []
    try:
        async with async_playwright() as driver:
            browser = await driver.chromium.connect_over_cdp(settings.cdp_url)
            for context in browser.contexts:
                for cookie in await context.cookies():
                    domain = str(cookie.get("domain") or "").lstrip(".")
                    if not domain or registered_domain(domain) != base:
                        continue
                    records.append(
                        CookieRecord(
                            name=str(cookie.get("name")),
                            value=str(cookie.get("value")),
                            domain=domain,
                            path=str(cookie.get("path") or "/"),
                            secure=bool(cookie.get("secure")),
                        )
                    )
            # The connection is dropped by leaving the context; the user's Chrome
            # is never closed.
    except Exception as exc:  # noqa: BLE001 - cookie sharing is best effort
        logger.debug("could not read cookies over CDP: %s", exc)
        return []
    if records:
        logger.info("shared %d session cookie(s) from the attached Chrome", len(records))
    return records


async def _launch_browser(driver: Any, settings: Settings) -> tuple[Any, Any, bool]:
    """Launch a fresh browser and create an isolated context.

    Args:
        driver: The active Playwright driver.
        settings: Active settings.

    Returns:
        A ``(browser, context, owns_browser=True)`` triple.
    """
    browser_type = getattr(driver, settings.browser, driver.chromium)
    launch_args: dict[str, Any] = {"headless": settings.browser_headless}
    if settings.proxy:
        launch_args["proxy"] = {"server": settings.proxy}
    browser = await browser_type.launch(**launch_args)
    context = await browser.new_context(
        user_agent=settings.user_agent,
        ignore_https_errors=not settings.verify_ssl,
        extra_http_headers=settings.headers or None,
        viewport={"width": 1440, "height": 900},
    )
    return browser, context, True


async def _attach_over_cdp(driver: Any, settings: Settings) -> tuple[Any, Any, bool]:
    """Attach to a Chrome the user is already running, over its DevTools endpoint.

    Whatever session that browser holds - including one that has already passed a
    challenge - is reused exactly as it stands. The tool neither creates nor
    circumvents that session, and it leaves the browser open afterwards.

    Args:
        driver: The active Playwright driver.
        settings: Active settings carrying ``cdp_url``.

    Returns:
        A ``(browser, context, owns_browser=False)`` triple, reusing the existing
        context so the live session's cookies apply.
    """
    browser = await driver.chromium.connect_over_cdp(settings.cdp_url)
    context = browser.contexts[0] if browser.contexts else await browser.new_context()
    logger.info("attached to existing Chrome at %s", settings.cdp_url)
    return browser, context, False


async def _seed_cookies(context: Any, url: str, settings: Settings) -> None:
    """Install user supplied cookies into the browser context.

    A session the user already established in their own browser - including a
    clearance cookie issued after they passed a challenge themselves - is the
    supported way to scan a protected target. Without this the browser started
    from scratch and threw that session away.

    Args:
        context: Playwright browser context.
        url: Any URL on the target, used to derive the cookie domain.
        settings: Active settings carrying the cookie jar.
    """
    records = settings.cookie_records()
    if not records:
        return
    host = urlsplit(url).hostname
    if not host:
        return
    cookies = [record.for_playwright(host) for record in records]
    with contextlib.suppress(Exception):
        await context.add_cookies(cookies)
        logger.debug("seeded %d cookie(s) into the browser context", len(cookies))


async def _capture_page(context: Any, url: str, settings: Settings) -> BrowserCapture:
    """Render one page inside an existing browser context."""
    capture_result = BrowserCapture(available=True)
    page = await context.new_page()
    try:
        _wire_listeners(page, context, capture_result, url)
        try:
            await page.goto(
                url, wait_until="domcontentloaded", timeout=settings.browser_timeout * 1000
            )
        except Exception as exc:  # noqa: BLE001 - navigation issues are reported
            capture_result.error = f"navigation: {type(exc).__name__}: {exc}"

        await _settle(page, settings.browser_settle)
        if settings.interact:
            capture_result.interactions = await _interact(page, settings)
            await _settle(page, min(settings.browser_settle, 3.0))

        capture_result.title = await _safe(page.title(), "")
        capture_result.html = await _safe(page.content(), "")
        capture_result.final_url = page.url
        capture_result.cookies = {
            str(cookie.get("name")): str(cookie.get("value")) for cookie in await context.cookies()
        }
        capture_result.storage_urls = await _storage_urls(page)
        capture_result.frameworks = await _framework_hints(page)
        capture_result.service_workers = [worker.url for worker in context.service_workers]
    except Exception as exc:  # noqa: BLE001
        capture_result.error = f"{type(exc).__name__}: {exc}"
    finally:
        with contextlib.suppress(Exception):
            await page.close()
    return capture_result


def _wire_listeners(page: Any, context: Any, capture_result: BrowserCapture, page_url: str) -> None:
    """Attach network, websocket, worker and console listeners to the page."""
    pending: dict[str, NetworkRequest] = {}

    def on_request(request: Any) -> None:
        record = NetworkRequest(
            url=request.url,
            method=request.method,
            resource_type=request.resource_type,
            initiator=page_url,
        )
        try:
            body = request.post_data
            if body:
                record.post_keys = _body_keys(body)
        except Exception:  # noqa: BLE001 - post data is best effort
            pass
        pending[_request_id(request)] = record
        capture_result.requests.append(record)

    def on_response(response: Any) -> None:
        record = pending.get(_request_id(response.request))
        if record is None:
            return
        record.status = response.status
        with contextlib.suppress(Exception):
            record.content_type = (response.headers.get("content-type") or "").split(";")[0].strip()

    def on_failed(request: Any) -> None:
        record = pending.get(_request_id(request))
        if record is not None:
            failure = getattr(request, "failure", None)
            record.failure = str(failure or "request failed")

    def on_websocket(socket: Any) -> None:
        if socket.url not in capture_result.websockets:
            capture_result.websockets.append(socket.url)

    def on_console(message: Any) -> None:
        if message.type == "error":
            capture_result.console_errors.append(str(message.text)[:300])

    def on_page_error(error: Any) -> None:
        capture_result.console_errors.append(str(error)[:300])

    def on_worker(worker: Any) -> None:
        if worker.url not in capture_result.service_workers:
            capture_result.service_workers.append(worker.url)

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("requestfailed", on_failed)
    page.on("websocket", on_websocket)
    page.on("console", on_console)
    page.on("pageerror", on_page_error)
    page.on("worker", on_worker)
    context.on("serviceworker", on_worker)


def _request_id(request: Any) -> str:
    """Build a stable identity for a Playwright request object."""
    return f"{id(request)}:{request.url}"


def _body_keys(body: str) -> list[str]:
    """Extract field names from a request body (JSON or form encoded)."""
    text = body.strip()
    if text.startswith("{"):
        try:
            import orjson

            data = orjson.loads(text)
        except Exception:  # noqa: BLE001
            return []
        if isinstance(data, dict):
            keys = [str(key) for key in data]
            if "query" in data and "operationName" in data:
                keys.append(f"gql:{data.get('operationName')}")
            return keys[:40]
        return []
    if "=" in text and "&" in text or ("=" in text and len(text) < 2048):
        return [pair.split("=", 1)[0] for pair in text.split("&") if "=" in pair][:40]
    return []


async def _settle(page: Any, seconds: float) -> None:
    """Wait for network idle, falling back to a fixed delay."""
    # ``networkidle`` never fires on pages with long-polling or analytics beacons.
    with contextlib.suppress(Exception):
        await page.wait_for_load_state("networkidle", timeout=max(seconds, 1.0) * 1000)
    if seconds > 0:
        await asyncio.sleep(min(seconds, 10.0))


async def _interact(page: Any, settings: Settings) -> int:
    """Scroll and click through the page to trigger lazy loaded requests.

    Args:
        page: Playwright page object.
        settings: Active settings, providing the interaction budget.

    Returns:
        The number of successful interactions.
    """
    performed = 0
    origin_url = page.url

    for selector in DISMISS_SELECTORS:
        try:
            element = await page.query_selector(selector)
            if element:
                await element.click(timeout=1500)
                performed += 1
        except Exception:  # noqa: BLE001
            continue

    # Progressive scroll to bottom to trigger infinite scroll handlers.
    try:
        for step in range(1, 6):
            await page.evaluate(f"window.scrollTo(0, document.body.scrollHeight * {step / 5})")
            await asyncio.sleep(0.6)
        await page.evaluate("window.scrollTo(0, 0)")
        performed += 1
    except Exception:  # noqa: BLE001
        pass

    budget = settings.max_interactions
    for selector in INTERACTION_SELECTORS:
        if performed >= budget:
            break
        try:
            elements = await page.query_selector_all(selector)
        except Exception:  # noqa: BLE001
            continue
        for element in elements[:5]:
            if performed >= budget:
                break
            try:
                if not await element.is_visible():
                    continue
                await element.click(timeout=1500, no_wait_after=True)
                performed += 1
                await asyncio.sleep(0.4)
                if page.url != origin_url:
                    await page.goto(origin_url, wait_until="domcontentloaded", timeout=15000)
                    await asyncio.sleep(0.5)
            except Exception:  # noqa: BLE001 - clicking arbitrary UI is inherently flaky
                continue
    return performed


async def _storage_urls(page: Any) -> list[str]:
    """Read URL-like values out of local and session storage."""
    script = """
    () => {
      const out = [];
      const scan = (store) => {
        try {
          for (let i = 0; i < store.length; i++) {
            const key = store.key(i);
            const value = String(store.getItem(key) || '');
            const matches = value.match(/https?:\\/\\/[^\\s"'<>\\\\]+/g);
            if (matches) out.push(...matches.slice(0, 20));
          }
        } catch (e) { /* storage may be blocked */ }
      };
      scan(window.localStorage);
      scan(window.sessionStorage);
      return out.slice(0, 200);
    }
    """
    try:
        values = await page.evaluate(script)
    except Exception:  # noqa: BLE001
        return []
    return [str(value) for value in values or []]


async def _framework_hints(page: Any) -> list[str]:
    """Fingerprint the front-end framework from the live DOM.

    This is the strongest available signal: it inspects the objects the framework
    actually attaches at runtime rather than guessing from file names.

    Args:
        page: Playwright page object, already loaded.

    Returns:
        Detected framework names, empty when nothing is recognised.
    """
    script = """
    () => {
      const found = new Set();
      const el = [...document.querySelectorAll('*')];
      if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
          document.querySelector('[data-reactroot]') ||
          el.some(e => Object.keys(e).some(k =>
              k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance')))) {
        found.add('React');
      }
      if (document.querySelector('[ng-version]') || window.getAllAngularRootElements ||
          (window.ng && window.ng.probe) || window.Zone) found.add('Angular');
      if (window.angular && window.angular.version) found.add('AngularJS');
      if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__ ||
          el.some(e => e.__vue__ || e.__vue_app__)) found.add('Vue');
      if (window.__NEXT_DATA__ || document.getElementById('__next')) found.add('Next.js');
      if (window.__NUXT__) found.add('Nuxt');
      if (window.jQuery && window.jQuery.fn) found.add('jQuery ' + (window.jQuery.fn.jquery || ''));
      if (window.L && window.L.TileLayer) found.add('Leaflet');
      if (window.ol && window.ol.Map) found.add('OpenLayers');
      if (window.mapboxgl || window.maplibregl) found.add('MapLibre/Mapbox');
      if (window.Cesium) found.add('Cesium');
      if (window.require && window.esri) found.add('ArcGIS API for JS');
      if (window.dataLayer || window.gtag) found.add('Google Analytics');
      const ver = document.querySelector('[ng-version]');
      if (ver) found.add('Angular ' + ver.getAttribute('ng-version'));
      return [...found];
    }
    """
    try:
        hints = await page.evaluate(script)
    except Exception:  # noqa: BLE001 - fingerprinting must never break a scan
        return []
    return [str(hint) for hint in hints or []]


async def _safe(awaitable: Any, default: Any) -> Any:
    """Await a coroutine, returning a default when it raises."""
    try:
        return await awaitable
    except Exception:  # noqa: BLE001
        return default
