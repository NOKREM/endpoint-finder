"""Tests for HTML extraction, asset classification and the domain models."""

from __future__ import annotations

from endpoint_finder.config import Settings
from endpoint_finder.crawler import assets as assetmod
from endpoint_finder.crawler import html as htmlmod
from endpoint_finder.models import (
    Confidence,
    Endpoint,
    EndpointCollector,
    EndpointType,
    HttpMethod,
    SourceKind,
)

PAGE = """<!doctype html>
<html><head>
  <title>Demo Portal</title>
  <base href="https://example.com/app/">
  <link rel="stylesheet" href="/static/app.css">
  <link rel="manifest" href="manifest.json">
  <meta name="generator" content="WordPress 6.5">
  <script src="/static/app.js"></script>
  <script>const cfg = {"apiUrl": "https://api.example.com"};</script>
  <script type="application/json">{"endpoint": "/api/embedded"}</script>
</head><body>
  <iframe src="/embed/frame.html"></iframe>
  <img src="/img/a.png" data-src="/api/image/1">
  <video src="/media/clip.mp4" poster="/img/p.jpg"></video>
  <source srcset="/img/a.webp 1x, /img/b.webp 2x">
  <embed src="/plugin/x.swf"><object data="/objects/y.pdf"></object>
  <a href="/products">Products</a><a href="https://other.com/x">External</a>
  <form action="/api/search" method="post"></form>
  <div data-api-url="/api/widget" hx-get="/api/htmx"></div>
  <style>.a{background:url(/api/bg.json)}</style>
</body></html>"""


def test_html_parse_resources() -> None:
    page = htmlmod.parse(PAGE, "https://example.com/index.html")
    assert page.title == "Demo Portal"
    assert page.base == "https://example.com/app/"
    assert "https://example.com/static/app.js" in page.scripts
    assert "https://example.com/static/app.css" in page.links
    assert "https://example.com/app/manifest.json" in page.links
    assert "https://example.com/embed/frame.html" in page.frames
    assert "https://example.com/img/a.png" in page.media
    assert "https://example.com/media/clip.mp4" in page.media
    assert "https://example.com/img/b.webp" in page.media
    assert "https://example.com/objects/y.pdf" in page.media
    assert "https://example.com/products" in page.anchors
    assert ("https://example.com/api/search", "POST") in page.forms
    assert "https://example.com/api/widget" in page.data_urls
    assert "https://example.com/api/htmx" in page.data_urls
    assert page.inline_scripts and "apiUrl" in page.inline_scripts[0]
    assert page.json_blobs and "/api/embedded" in page.json_blobs[0]
    assert page.inline_styles


def test_html_parse_handles_empty_and_broken() -> None:
    assert htmlmod.parse("", "https://x.com/").title == ""
    assert htmlmod.parse("<html><body><p>unclosed", "https://x.com/").url == "https://x.com/"


def test_detect_technologies() -> None:
    page = htmlmod.parse(PAGE, "https://example.com/index.html")
    tech = htmlmod.detect_technologies(page, {"Server": "nginx/1.24"})
    assert "WordPress" in tech
    assert "nginx/1.24" in tech


def test_detect_from_source_identifies_hashed_bundles() -> None:
    # A CRA/Vite bundle name gives nothing away; the contents do.
    react_bundle = "var x=1;window.__REACT_DEVTOOLS_GLOBAL_HOOK__;useLayoutEffect(function(){})"
    assert "React" in htmlmod.detect_from_source(react_bundle)

    angular_bundle = "ɵɵdefineComponent({});platformBrowserDynamic().bootstrapModule(NgModule)"
    detected = htmlmod.detect_from_source(angular_bundle)
    assert "Angular" in detected
    assert "React" not in detected


def test_detect_from_source_does_not_fire_on_generic_dom_calls() -> None:
    # document.createElement is not evidence of React.
    plain = "var el = document.createElement('div'); el.render = null; container.appendChild(el);"
    assert htmlmod.detect_from_source(plain) == set()


def test_detect_from_source_finds_mapping_libraries() -> None:
    assert "Leaflet" in htmlmod.detect_from_source("var m=L.TileLayer.extend({});")
    assert "OpenLayers" in htmlmod.detect_from_source("import Map from 'ol/Map';")


def test_classify_asset() -> None:
    assert assetmod.classify_asset("https://x.com/a.js") == "js"
    assert assetmod.classify_asset("https://x.com/a.js.map") == "map"
    assert assetmod.classify_asset("https://x.com/a.css") == "css"
    assert assetmod.classify_asset("https://x.com/a.geojson") == "json"
    assert assetmod.classify_asset("https://x.com/data", "application/json") == "json"
    assert assetmod.classify_asset("https://x.com/x", "image/png") == "other"


def test_asset_queue_filters_and_bounds() -> None:
    settings = Settings(target="https://example.com", max_assets=3)
    queue = assetmod.AssetQueue(settings=settings, target="https://example.com")

    assert queue.push("https://example.com/a.js")
    assert not queue.push("https://example.com/a.js")  # duplicate
    assert not queue.push("https://example.com/logo.png")  # binary
    assert not queue.push("https://example.com/page")  # not analysable
    assert queue.push("https://example.com/x.map", force=True)
    assert queue.push("https://example.com/b.js")
    assert not queue.push("https://example.com/c.js")  # over max_assets

    pending = queue.drain()
    assert len(pending) == 3
    assert not queue.has_pending
    assert len(queue.records) == 3


def test_collector_deduplicates_and_merges() -> None:
    collector = EndpointCollector()
    collector.add(
        Endpoint(
            url="https://x.com/api/a",
            method=HttpMethod.GET,
            type=EndpointType.UNKNOWN,
            confidence=Confidence.LOW,
            source=SourceKind.JAVASCRIPT,
            params=["a"],
        )
    )
    collector.add(
        Endpoint(
            url="https://x.com/api/a",
            method=HttpMethod.GET,
            type=EndpointType.REST,
            confidence=Confidence.HIGH,
            source=SourceKind.NETWORK,
            status_code=200,
            content_type="application/json",
            params=["b"],
            evidence="observed",
        )
    )
    collector.add(
        Endpoint(url="https://x.com/api/a", method=HttpMethod.POST, source=SourceKind.JAVASCRIPT)
    )

    assert len(collector) == 2
    merged = next(e for e in collector.sorted() if e.method is HttpMethod.GET)
    assert merged.type is EndpointType.REST
    assert merged.confidence is Confidence.HIGH
    assert merged.status_code == 200
    assert merged.params == ["a", "b"]


def test_prefer_observed_methods_drops_guesses() -> None:
    from endpoint_finder.discovery import api as apimod

    proven = Endpoint(
        url="https://x.com/api/items/save", method=HttpMethod.PUT, method_observed=True
    )
    guessed = Endpoint(url="https://x.com/api/items/save", method=HttpMethod.POST)
    untouched = Endpoint(url="https://x.com/api/other", method=HttpMethod.POST)

    kept = apimod.prefer_observed_methods([proven, guessed, untouched])
    assert proven in kept
    assert guessed not in kept
    assert untouched in kept


def test_merge_keeps_observed_method_flag() -> None:
    collector = EndpointCollector()
    collector.add(Endpoint(url="https://x.com/a", method=HttpMethod.GET))
    collector.add(Endpoint(url="https://x.com/a", method=HttpMethod.GET, method_observed=True))
    assert collector.sorted()[0].method_observed is True


def test_endpoint_evidence_is_trimmed() -> None:
    endpoint = Endpoint(url="https://x.com/a", evidence="  many\n\nspaces   here " + "x" * 400)
    assert endpoint.evidence is not None
    assert len(endpoint.evidence) <= 240
    assert "\n" not in endpoint.evidence
