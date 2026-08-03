"""End-to-end pipeline tests with a fully mocked network."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import orjson
import pytest
import respx

from endpoint_finder.config import Settings
from endpoint_finder.models import EndpointType, HttpMethod, SourceKind
from endpoint_finder.net.client import AsyncHttpClient
from endpoint_finder.net.errors import ErrorCategory, classify_response
from endpoint_finder.pipeline import normalise_target, scan

INDEX = """<!doctype html>
<html><head><title>Mock Portal</title>
<script src="/static/app.js"></script>
<script>const cfg={"API_URL":"https://api.example.com"};</script>
</head><body>
<form action="/api/search" method="post"></form>
<a href="/detail">Detail</a>
<div data-api-url="/api/widget"></div>
</body></html>"""

DETAIL = """<!doctype html><html><head><title>Detail</title></head>
<body><script>fetch("/api/v1/detail/items");</script></body></html>"""

APP_JS = """
const API_URL = "https://api.example.com";
fetch("/api/v1/users", { method: "POST" });
axios.get("/api/v1/orders");
new WebSocket("wss://live.example.com/feed");
const spec = "/openapi.json";
const gis = "https://gis.example.com/arcgis/rest/services/City/MapServer";
//# sourceMappingURL=/static/app.js.map
"""

APP_MAP = orjson.dumps(
    {
        "version": 3,
        "sources": ["src/secret.js"],
        "sourcesContent": ['fetch("/api/v1/internal/audit");'],
    }
).decode()

OPENAPI = orjson.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "Mock"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {"/v1/reports": {"get": {"operationId": "reports"}}},
    }
).decode()

ROBOTS = "User-agent: *\nDisallow: /admin/api/\nSitemap: https://example.com/sitemap.xml\n"

SITEMAP = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/api/v1/public.json</loc></url>
</urlset>"""


def _mock_routes(router: respx.Router) -> None:
    """Register every mocked response used by the pipeline tests."""
    router.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            html=INDEX,
            headers={"content-security-policy": "connect-src 'self' https://cdn.example.com"},
        )
    )
    router.get("https://example.com/detail").mock(return_value=httpx.Response(200, html=DETAIL))
    router.get("https://example.com/static/app.js").mock(
        return_value=httpx.Response(
            200, text=APP_JS, headers={"content-type": "application/javascript"}
        )
    )
    router.get("https://example.com/static/app.js.map").mock(
        return_value=httpx.Response(200, text=APP_MAP, headers={"content-type": "application/json"})
    )
    router.get("https://example.com/openapi.json").mock(
        return_value=httpx.Response(200, text=OPENAPI, headers={"content-type": "application/json"})
    )
    router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text=ROBOTS))
    router.get("https://example.com/sitemap.xml").mock(
        return_value=httpx.Response(200, text=SITEMAP, headers={"content-type": "application/xml"})
    )
    router.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nope"))


@pytest.fixture
def scan_settings(settings: Settings) -> Settings:
    """Pipeline settings with crawling enabled but the browser disabled."""
    settings.depth = 1
    settings.probe = True
    return settings


@respx.mock
async def test_full_scan(scan_settings: Settings) -> None:
    _mock_routes(respx.mock)
    result = await scan(scan_settings)

    urls = {endpoint.url for endpoint in result.endpoints}

    # HTML
    assert "https://example.com/api/search" in urls
    assert "https://example.com/api/widget" in urls
    # JavaScript
    assert "https://example.com/api/v1/users" in urls
    assert "https://api.example.com/api/v1/users" in urls
    assert "wss://live.example.com/feed" in urls
    # crawl depth
    assert "https://example.com/api/v1/detail/items" in urls
    # source map
    assert "https://example.com/api/v1/internal/audit" in urls
    # openapi expansion
    assert "https://api.example.com/v1/reports" in urls
    # metadata
    assert "https://example.com/admin/api/" in urls
    assert "https://example.com/api/v1/public.json" in urls
    # arcgis
    assert "https://gis.example.com/arcgis/rest/services/City/MapServer" in urls

    types = {endpoint.type for endpoint in result.endpoints}
    assert {EndpointType.REST, EndpointType.WEBSOCKET, EndpointType.ARCGIS} <= types

    assert result.page_title == "Mock Portal"
    assert result.stats.pages == 2
    assert result.stats.scripts >= 1
    assert result.stats.sourcemaps == 1

    search = next(e for e in result.endpoints if e.url.endswith("/api/search"))
    assert search.method is HttpMethod.POST
    assert search.source is SourceKind.HTML


@respx.mock
async def test_scan_is_deduplicated(scan_settings: Settings) -> None:
    _mock_routes(respx.mock)
    result = await scan(scan_settings)
    keys = [(endpoint.method, endpoint.url) for endpoint in result.endpoints]
    assert len(keys) == len(set(keys))


@respx.mock
async def test_scan_records_errors_without_failing(scan_settings: Settings) -> None:
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, html=INDEX))
    respx.get("https://example.com/static/app.js").mock(side_effect=httpx.ConnectTimeout("boom"))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

    scan_settings.depth = 0
    result = await scan(scan_settings)
    assert any(error.category == ErrorCategory.TIMEOUT.value for error in result.errors)
    assert result.endpoints  # the page itself still produced endpoints


@respx.mock
async def test_include_exclude_filters(scan_settings: Settings) -> None:
    _mock_routes(respx.mock)
    scan_settings.include = [r"/api/"]
    result = await scan(scan_settings)
    assert result.endpoints
    assert all("/api/" in endpoint.url for endpoint in result.endpoints)


@respx.mock
async def test_host_filter_beats_include_for_scoping(scan_settings: Settings) -> None:
    tracker = "https://tracker.example.net/watch?page-url=https%3A%2F%2Fexample.com%2F"
    page = (
        f'<html><head><title>T</title></head><body><script>fetch("{tracker}");'
        "</script></body></html>"
    )
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, html=page))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    scan_settings.depth = 0

    # --include matches the whole URL, so the tracker slips through on its query.
    scan_settings.include = [r"example\.com"]
    scan_settings.hosts = []
    with_include = await scan(scan_settings)
    assert any("tracker.example.net" in e.url for e in with_include.endpoints)

    # --host looks at the hostname only and keeps it out.
    scan_settings.include = []
    scan_settings.hosts = ["example.com"]
    with_host = await scan(scan_settings)
    assert not any("tracker.example.net" in e.url for e in with_host.endpoints)
    assert all(
        urlsplit(e.url).hostname and urlsplit(e.url).hostname.endswith("example.com")
        for e in with_host.endpoints
    )


@respx.mock
async def test_host_filter_accepts_subdomains_and_url_forms(scan_settings: Settings) -> None:
    _mock_routes(respx.mock)
    scan_settings.hosts = ["*.example.com"]
    result = await scan(scan_settings)
    hosts = {urlsplit(e.url).hostname for e in result.endpoints}
    assert "api.example.com" in hosts
    assert "example.com" in hosts
    assert "gis.example.com" in hosts, "subdomains of the suffix stay in scope"
    assert all(host == "example.com" or host.endswith(".example.com") for host in hosts if host)


@respx.mock
async def test_exclude_host_stops_the_fetch_as_well(scan_settings: Settings) -> None:
    page = (
        "<html><head><title>T</title>"
        '<script src="https://cdn.tracker.net/t.js"></script>'
        '<script src="/static/app.js"></script>'
        "</head><body></body></html>"
    )
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, html=page))
    respx.get("https://example.com/static/app.js").mock(
        return_value=httpx.Response(
            200, text=APP_JS, headers={"content-type": "application/javascript"}
        )
    )
    tracker_route = respx.get("https://cdn.tracker.net/t.js").mock(
        return_value=httpx.Response(
            200,
            text='fetch("https://cdn.tracker.net/collect");',
            headers={"content-type": "application/javascript"},
        )
    )
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    scan_settings.depth = 0
    scan_settings.exclude_hosts = ["tracker.net"]

    result = await scan(scan_settings)

    assert tracker_route.call_count == 0, "an excluded host must never be requested"
    assert not any("tracker.net" in e.url for e in result.endpoints)
    # The rest of the scan is unaffected.
    assert any(e.url == "https://example.com/api/v1/users" for e in result.endpoints)


def test_absorb_forms_captures_browser_rendered_forms() -> None:
    from endpoint_finder.models import EndpointCollector
    from endpoint_finder.pipeline import _absorb_forms, _State

    state = _State(settings=Settings(target="https://example.com"), target="https://example.com/")
    state.collector = EndpointCollector()
    _absorb_forms(
        state,
        [("https://account.example.com/Login/Now", "POST")],
        "https://account.example.com/Login",
    )
    endpoints = state.collector.sorted()
    assert len(endpoints) == 1
    assert endpoints[0].url == "https://account.example.com/Login/Now"
    assert endpoints[0].method is HttpMethod.POST
    assert "form" in endpoints[0].tags


def test_select_render_targets_prefers_script_heavy_pages() -> None:
    from endpoint_finder.pipeline import select_render_targets

    target = "https://example.com/"
    candidates = [
        (target, 2),
        ("https://example.com/plain", 0),
        ("https://example.com/app", 9),
        ("https://example.com/maps", 5),
    ]
    assert select_render_targets(target, candidates, 3) == [
        target,
        "https://example.com/app",
        "https://example.com/maps",
    ]
    # The entry page is always rendered, even with a budget of one.
    assert select_render_targets(target, candidates, 1) == [target]
    # No duplicates when the target also appears in the candidate list.
    assert select_render_targets(target, [(target, 3)], 5) == [target]


@respx.mock
async def test_http_client_retries_then_succeeds(settings: Settings) -> None:
    settings.retries = 2
    route = respx.get("https://example.com/flaky")
    route.side_effect = [
        httpx.ConnectTimeout("t1"),
        httpx.Response(200, text="ok"),
    ]
    async with AsyncHttpClient(settings) as client:
        result = await client.get("https://example.com/flaky")
    assert result.ok
    assert result.text == "ok"
    assert route.call_count == 2


@respx.mock
async def test_http_client_reports_failure_categories(settings: Settings) -> None:
    respx.get("https://example.com/403").mock(return_value=httpx.Response(403, text="denied"))
    respx.get("https://example.com/dns").mock(side_effect=httpx.ConnectError("getaddrinfo failed"))
    async with AsyncHttpClient(settings) as client:
        forbidden = await client.get("https://example.com/403")
        dns = await client.get("https://example.com/dns")
    assert forbidden.error is ErrorCategory.FORBIDDEN
    assert dns.error is ErrorCategory.DNS


def test_cloudflare_challenge_detection() -> None:
    category = classify_response(503, {"Server": "cloudflare"}, "<title>Just a moment...</title>")
    assert category is ErrorCategory.CLOUDFLARE


@pytest.mark.parametrize(
    ("status", "headers", "body", "expected"),
    [
        (200, {"cf-ray": "abc"}, "<title>Just a moment...</title>", ErrorCategory.CLOUDFLARE),
        (403, {"server": "cloudflare"}, "you have been blocked", ErrorCategory.CLOUDFLARE),
        (429, {"cf-mitigated": "challenge"}, "", ErrorCategory.CLOUDFLARE),
        (403, {"x-sucuri-block": "1"}, "access denied | site", ErrorCategory.WAF),
        (403, {"x-iinfo": "9-1"}, "Request unsuccessful. Incapsula", ErrorCategory.WAF),
        (403, {"x-datadome": "protected"}, "captcha-delivery.com", ErrorCategory.WAF),
        # A plain 403 with no protection layer stays a plain 403.
        (403, {"server": "nginx"}, "forbidden", ErrorCategory.FORBIDDEN),
        (200, {"server": "nginx"}, "<html>real content</html>", None),
    ],
)
def test_protection_layers_are_classified(
    status: int, headers: dict[str, str], body: str, expected: ErrorCategory | None
) -> None:
    assert classify_response(status, headers, body) is expected


def test_protection_vendor_detection() -> None:
    from endpoint_finder.net.errors import protection_vendor

    assert protection_vendor({"cf-ray": "x"}) == "Cloudflare"
    assert protection_vendor({"x-akamai-transformed": "9"}) == "Akamai"
    assert protection_vendor({"x-amzn-waf-action": "block"}) == "AWS WAF"
    assert protection_vendor({"server": "nginx"}, "<html>ok</html>") is None


def test_challenge_page_detected_behind_a_200() -> None:
    from endpoint_finder.net.errors import is_challenge_page

    # The dangerous case: a challenge served with a success status, whose body
    # would otherwise be parsed as if it were the real page.
    assert is_challenge_page(200, {"cf-ray": "x"}, "<title>Just a moment...</title>")
    assert not is_challenge_page(200, {"server": "nginx"}, "<html><body>real</body></html>")


def test_real_page_embedding_a_captcha_widget_is_not_a_challenge() -> None:
    from endpoint_finder.net.errors import classify_response, is_challenge_page

    # A genuine login page that embeds a Turnstile widget for its own form must
    # not be discarded as a challenge - it carries real content and endpoints.
    login = (
        "<title>DF Manage Acct</title>"
        '<form action="/Login/Now" method="post">'
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
        "</form>"
    )
    assert not is_challenge_page(200, {"cf-ray": "x"}, login)
    assert classify_response(200, {"cf-ray": "x"}, login) is None


@respx.mock
async def test_client_slows_down_after_a_challenge(settings: Settings) -> None:
    settings.retries = 0
    respx.get("https://example.com/blocked").mock(
        return_value=httpx.Response(
            503, headers={"server": "cloudflare"}, text="<title>Just a moment...</title>"
        )
    )
    async with AsyncHttpClient(settings) as client:
        assert client._penalty == 0.0
        result = await client.get("https://example.com/blocked")
        assert result.error is ErrorCategory.CLOUDFLARE
        assert client.protection == "Cloudflare"
        assert client.challenges == 1
        # Being challenged must make the scan gentler, not more aggressive.
        assert client._penalty > 0.0


@respx.mock
async def test_server_errors_do_not_throttle_the_whole_scan(settings: Settings) -> None:
    settings.retries = 0
    respx.get("https://example.com/broken").mock(return_value=httpx.Response(500, text="oops"))
    respx.get("https://example.com/fine").mock(return_value=httpx.Response(200, text="ok"))
    async with AsyncHttpClient(settings) as client:
        await client.get("https://example.com/broken")
        # One broken endpoint is not the target asking for less traffic.
        assert client._penalty == 0.0
        assert client.challenges == 0
        assert (await client.get("https://example.com/fine")).ok


@respx.mock
async def test_penalty_decays_once_the_target_recovers(settings: Settings) -> None:
    settings.retries = 0
    respx.get("https://example.com/blocked").mock(
        return_value=httpx.Response(429, headers={"cf-mitigated": "challenge"})
    )
    respx.get("https://example.com/ok").mock(return_value=httpx.Response(200, text="ok"))
    async with AsyncHttpClient(settings) as client:
        await client.get("https://example.com/blocked")
        peak = client._penalty
        assert peak > 0
        for _ in range(6):
            await client.get(f"https://example.com/ok?{_}")
        assert client._penalty < peak / 4


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("http://example.com/a/", "http://example.com/a/"),
    ],
)
def test_normalise_target(raw: str, expected: str) -> None:
    assert normalise_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://x.com"])
def test_normalise_target_rejects_bad_input(raw: str) -> None:
    with pytest.raises(ValueError, match="empty|usable"):
        normalise_target(raw)
