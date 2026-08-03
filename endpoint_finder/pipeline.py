"""Scan orchestration: wires crawling, analysis, discovery and reporting together."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from endpoint_finder.config import SCHEMA_PROBE_PATHS, WELL_KNOWN_PATHS, Settings
from endpoint_finder.crawler import assets as assetmod
from endpoint_finder.crawler import browser as browsermod
from endpoint_finder.crawler import html as htmlmod
from endpoint_finder.crawler import javascript as jsmod
from endpoint_finder.crawler.spider import Spider
from endpoint_finder.discovery import api as apimod
from endpoint_finder.discovery import arcgis, geoserver, graphql, swagger, websocket
from endpoint_finder.discovery.classifier import classify, guess_method
from endpoint_finder.logging_setup import console, get_logger
from endpoint_finder.models import (
    Confidence,
    Endpoint,
    EndpointCollector,
    EndpointType,
    HttpMethod,
    ScanError,
    ScanResult,
    ScanStats,
    SourceKind,
)
from endpoint_finder.net.client import AsyncHttpClient, FetchResult
from endpoint_finder.parser import metadata, sourcemap
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import AnalysisContext
from endpoint_finder.verify import verify_endpoints

logger = get_logger(__name__)

MAX_SOURCEMAP_DEPTH = 2


@dataclass(slots=True)
class _State:
    """Mutable working state shared by the pipeline stages."""

    settings: Settings
    target: str
    collector: EndpointCollector = field(default_factory=EndpointCollector)
    stats: ScanStats = field(default_factory=ScanStats)
    errors: list[ScanError] = field(default_factory=list)
    technologies: set[str] = field(default_factory=set)
    base_urls: list[str] = field(default_factory=list)
    schema_urls: list[str] = field(default_factory=list)
    arcgis_services: list[str] = field(default_factory=list)
    ogc_services: list[str] = field(default_factory=list)
    graphql_urls: list[str] = field(default_factory=list)
    sourcemap_urls: list[str] = field(default_factory=list)
    page_title: str = ""
    #: ``(url, script_count)`` for every crawled page, used to pick render targets.
    page_candidates: list[tuple[str, int]] = field(default_factory=list)
    #: Client side routes recovered from bundles and rendered DOM links.
    spa_routes: list[str] = field(default_factory=list)
    rendered_pages: int = 0
    protection: str | None = None
    challenges: int = 0

    def context(self, source_url: str, kind: SourceKind) -> AnalysisContext:
        """Build an analysis context for one artefact."""
        return AnalysisContext(
            source_url=source_url,
            source_kind=kind,
            target=self.target,
            follow_subdomains=self.settings.follow_subdomains,
            keep_external=True,
            include=self.settings.include_patterns,
            exclude=self.settings.exclude_patterns,
        )

    def record_error(self, url: str, result: FetchResult) -> None:
        """Store a failed fetch in the report."""
        if result.error is None:
            return
        self.errors.append(
            ScanError(
                url=url, category=result.error.value, message=result.message or str(result.error)
            )
        )

    def remember(self, bucket: list[str], value: str, limit: int = 60) -> None:
        """Append a value to a bounded, deduplicated bucket."""
        if value not in bucket and len(bucket) < limit:
            bucket.append(value)


def _origin(url: str) -> str:
    """Return the scheme+host origin of a URL."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def normalise_target(raw: str) -> str:
    """Turn user input into an absolute, normalised target URL.

    Args:
        raw: Whatever the user typed, e.g. ``example.com`` or ``https://x.com/a``.

    Returns:
        A normalised absolute URL.

    Raises:
        ValueError: When the input cannot be interpreted as an HTTP(S) URL.
    """
    candidate = raw.strip()
    if not candidate:
        msg = "target URL is empty"
        raise ValueError(msg)
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    normalised = urlutil.normalize(candidate)
    if not normalised or not normalised.startswith(("http://", "https://")):
        msg = f"not a usable HTTP(S) URL: {raw!r}"
        raise ValueError(msg)
    return normalised


async def scan(settings: Settings) -> ScanResult:
    """Run a complete passive discovery scan.

    Args:
        settings: Fully populated settings including the target.

    Returns:
        The :class:`~endpoint_finder.models.ScanResult` for the target.
    """
    started = time.perf_counter()
    target = normalise_target(settings.target)
    state = _State(settings=settings, target=target)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TextColumn("{task.fields[detail]}"),
        console=console,
        transient=True,
        disable=settings.quiet,
    )

    async with AsyncHttpClient(settings) as client:
        with progress:
            task = progress.add_task("scanning", total=6, detail="")

            if settings.cdp_url:
                # Share the session the user cleared in their own Chrome with the
                # static HTTP client, so both sides reuse it rather than the
                # httpx side being challenged on its own.
                shared = await browsermod.harvest_cdp_cookies(
                    settings, urlsplit(target).hostname or ""
                )
                client.add_session_cookies(shared)

            progress.update(task, description="metadata", detail=urlsplit(target).netloc)
            await _stage_metadata(client, state)
            progress.advance(task)

            progress.update(task, description="crawling pages", detail="")
            queue = assetmod.AssetQueue(settings=settings, target=target)
            pages = await _stage_pages(client, state, queue, progress, task)
            progress.advance(task)

            progress.update(task, description="analysing assets", detail=f"{len(queue)} queued")
            await _stage_assets(client, state, queue, progress, task)
            progress.advance(task)

            progress.update(task, description="browser capture", detail="")
            await _stage_browser(state, queue, client)
            progress.advance(task)

            progress.update(task, description="schema expansion", detail="")
            await _stage_schemas(client, state)
            progress.advance(task)

            endpoints, routes = _select_endpoints(state)

            if settings.verify:
                progress.update(task, description="verifying endpoints", detail="")
                state.stats.verified = await verify_endpoints(
                    client, endpoints, concurrency=settings.concurrency
                )

            progress.update(task, description="finalising", detail="")
            state.protection = client.protection
            state.challenges = client.challenges
            result = _finalise(state, endpoints, routes, pages, queue, started)
            progress.advance(task)

    return result


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------
async def _stage_metadata(client: AsyncHttpClient, state: _State) -> None:
    """Fetch and parse robots.txt, sitemaps, manifests and well-known documents."""
    origin = _origin(state.target)
    urls = [f"{origin}{path}" for path in WELL_KNOWN_PATHS]
    results = await client.get_many(urls)

    sitemaps: list[str] = []
    for url, result in zip(urls, results, strict=True):
        if not result.ok:
            if result.error and result.error.value not in {"http_404", "http_403"}:
                state.record_error(url, result)
            continue
        lowered = url.lower()
        if lowered.endswith("robots.txt"):
            endpoints, found = metadata.parse_robots(result.text, result.url)
            state.collector.extend(endpoints)
            sitemaps.extend(found)
        elif "sitemap" in lowered:
            sitemaps.append(result.url)
        elif "manifest" in lowered:
            state.collector.extend(metadata.parse_manifest(result.text, result.url))
        elif "/.well-known/" in lowered:
            state.collector.extend(metadata.parse_well_known(result.text, result.url))

    await _consume_sitemaps(client, state, sitemaps)


async def _consume_sitemaps(client: AsyncHttpClient, state: _State, seeds: list[str]) -> None:
    """Follow sitemap indexes one level deep and record interesting URLs."""
    seen: set[str] = set()
    frontier = [url for url in dict.fromkeys(seeds) if url]
    depth = 0
    while frontier and depth < 2:
        batch = [url for url in frontier[:20] if url not in seen]
        seen.update(batch)
        frontier = frontier[20:]
        if not batch:
            break
        results = await client.get_many(batch)
        nested: list[str] = []
        for url, result in zip(batch, results, strict=True):
            if not result.ok:
                continue
            pages, children = metadata.parse_sitemap(result.text, result.url)
            nested.extend(children)
            for page in pages[:500]:
                etype = classify(page, hint="sitemap")
                if etype is EndpointType.UNKNOWN:
                    continue
                state.collector.add(
                    Endpoint(
                        url=page,
                        method=guess_method(page, etype),
                        type=etype,
                        source=SourceKind.SITEMAP,
                        source_url=url,
                        evidence="sitemap <loc>",
                        confidence=Confidence.MEDIUM,
                    )
                )
        frontier.extend(nested)
        depth += 1


async def _stage_pages(
    client: AsyncHttpClient,
    state: _State,
    queue: assetmod.AssetQueue,
    progress: Progress,
    task: Any,
) -> int:
    """Crawl HTML pages, extract their resources and analyse inline code."""
    spider = Spider(client, state.settings, state.target)
    count = 0

    async for page in spider.crawl():
        count += 1
        data = page.data
        if count == 1:
            state.page_title = data.title
            state.collector.extend(metadata.parse_headers(page.result.headers, page.result.url))
        state.technologies.update(htmlmod.detect_technologies(data, page.result.headers))
        progress.update(task, detail=f"page {count}: {urlsplit(data.url).path[:40]}")
        state.page_candidates.append((data.url, len(data.scripts) + len(data.inline_scripts)))

        _absorb_forms(state, data.forms, data.url)

        for url in [*data.data_urls, *data.meta_urls, *data.media, *data.links, *data.frames]:
            _add_resource_endpoint(state, url, data.url)

        queue.push_many(data.scripts, data.url)
        queue.push_many([url for url in data.links if urlutil.is_analysable(url)], data.url)
        queue.push_many([url for url in data.media if urlutil.is_analysable(url)], data.url)
        queue.push_many([url for url in data.data_urls if urlutil.is_analysable(url)], data.url)

        ctx_template = state.context(data.url, SourceKind.HTML)
        if data.inline_scripts:
            analysis = jsmod.analyze_inline_scripts(data.inline_scripts, data.url, ctx_template)
            _absorb(state, analysis, queue)
        if data.json_blobs:
            analysis = jsmod.analyze_json_blobs(data.json_blobs, data.url, ctx_template)
            _absorb(state, analysis, queue)
        if data.inline_styles:
            css_ctx = state.context(data.url, SourceKind.CSS)
            _absorb(state, jsmod.analyze_asset("\n".join(data.inline_styles), css_ctx), queue)

    state.stats.pages = count
    for failure in spider.failures:
        state.record_error(failure.requested_url, failure)
    return count


def _absorb_forms(state: _State, forms: list[tuple[str, str]], page_url: str) -> None:
    """Turn ``<form action>`` targets into endpoints.

    Shared by the static crawl and the browser stage: a login form on a page that
    only the real browser could reach (a separately protected subdomain, say) is
    just as much an endpoint as one on a statically fetched page.

    Args:
        state: Current scan state.
        forms: ``(action_url, method)`` pairs from a parsed page.
        page_url: URL the forms were found on.
    """
    for form_url, method in forms:
        etype = classify(form_url, hint="form")
        state.collector.add(
            Endpoint(
                url=form_url,
                method=HttpMethod(method),
                method_observed=True,
                type=EndpointType.REST if etype is EndpointType.UNKNOWN else etype,
                source=SourceKind.HTML,
                source_url=page_url,
                evidence=f"<form action> {method}",
                confidence=Confidence.HIGH,
                tags=["form"],
            )
        )


def _add_resource_endpoint(state: _State, url: str, page_url: str) -> None:
    """Record a referenced resource when it classifies as an endpoint."""
    etype = classify(url, hint="html")
    if etype is EndpointType.UNKNOWN:
        return
    state.collector.add(
        Endpoint(
            url=url,
            method=guess_method(url, etype),
            type=etype,
            source=SourceKind.HTML,
            source_url=page_url,
            evidence="referenced in markup",
            confidence=Confidence.MEDIUM,
        )
    )


async def _stage_assets(
    client: AsyncHttpClient,
    state: _State,
    queue: assetmod.AssetQueue,
    progress: Progress,
    task: Any,
) -> None:
    """Download and analyse every queued asset, following source maps."""
    rounds = 0
    while queue.has_pending and rounds < 8:
        rounds += 1
        batch = queue.drain()
        progress.update(task, detail=f"{len(batch)} assets (round {rounds})")
        downloaded = await assetmod.download(client, batch)

        for url, result, kind in downloaded:
            if not result.ok:
                state.record_error(url, result)
                continue
            if not assetmod.is_textual(result):
                continue
            state.stats.assets_downloaded += 1
            state.stats.bytes_downloaded += result.size
            if kind == "js":
                state.stats.scripts += 1
            elif kind == "css":
                state.stats.stylesheets += 1

            await _analyse_document(state, queue, result, kind)

    # Source maps are fetched last so that they cannot starve the asset budget.
    if state.settings.analyse_sourcemaps and state.sourcemap_urls:
        await _stage_sourcemaps(client, state, queue)


async def _analyse_document(
    state: _State, queue: assetmod.AssetQueue, result: FetchResult, kind: str
) -> None:
    """Dispatch one downloaded document to the right analyser."""
    url = result.url
    text = result.text

    # Structured API descriptions get expanded instead of regex-scraped.
    if kind in {"json", "yaml"} or swagger.looks_like_swagger(url):
        expanded = swagger.analyze(text, url, result.content_type)
        if expanded:
            state.collector.extend(expanded)
            return
    if kind == "json" and arcgis.is_catalog_document(text):
        state.collector.extend(arcgis.parse_catalog(text, url))
    if kind == "xml" and geoserver.is_capabilities_document(text):
        state.collector.extend(geoserver.parse_capabilities(text, url))

    source_kind = {
        "js": SourceKind.JAVASCRIPT,
        "map": SourceKind.SOURCEMAP,
        "css": SourceKind.CSS,
        "json": SourceKind.JSON,
        "yaml": SourceKind.JSON,
        "xml": SourceKind.XML,
        "html": SourceKind.HTML,
    }.get(kind, SourceKind.JAVASCRIPT)

    if kind == "map":
        endpoints, parsed = sourcemap.analyze(text, url, state.context(url, SourceKind.SOURCEMAP))
        state.collector.extend(endpoints)
        if parsed is not None:
            state.stats.sourcemaps += 1
            for original in sourcemap.original_source_urls(parsed)[:50]:
                queue.push(original, url)
        return

    if kind == "js":
        # Hashed bundle names carry no brand, so the build output can only be
        # identified from its contents.
        state.technologies.update(htmlmod.detect_from_source(text))

    ctx = state.context(url, source_kind)
    # Base URLs are deliberately *not* shared between assets: joining a path from
    # one bundle onto a host declared in an unrelated bundle invents endpoints.
    # Each asset is resolved against its own configuration constants only.
    analysis = jsmod.analyze_asset(text, ctx)
    _absorb(state, analysis, queue)


#: Extensions of endpoints that are themselves worth downloading and re-analysing.
_CHAINABLE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".json", ".map"})


def _absorb(state: _State, analysis: jsmod.AssetAnalysis, queue: assetmod.AssetQueue) -> None:
    """Fold an asset analysis into the shared state."""
    state.collector.extend(analysis.endpoints)
    for endpoint in analysis.endpoints:
        # Chunks referenced from JavaScript (dynamic imports, script injection,
        # config JSON) never appear in the markup, so queue them explicitly.
        if urlutil.extension(endpoint.url) in _CHAINABLE_EXTENSIONS:
            queue.push(endpoint.url, endpoint.source_url)
    for base in analysis.base_urls:
        state.remember(state.base_urls, base, limit=25)
    for schema_url in analysis.schema_urls:
        state.remember(state.schema_urls, schema_url)
    for graphql_url in analysis.graphql_urls:
        state.remember(state.graphql_urls, graphql_url)
    for route in analysis.spa_routes:
        if urlutil.same_scope(
            route, state.target, follow_subdomains=state.settings.follow_subdomains
        ):
            state.remember(state.spa_routes, route, limit=200)
    for service in analysis.service_urls:
        if arcgis.detect_service(service):
            state.remember(state.arcgis_services, service)
        elif geoserver.detect_service(service):
            state.remember(state.ogc_services, service)
    if analysis.sourcemap_url:
        state.remember(state.sourcemap_urls, analysis.sourcemap_url, limit=200)


async def _stage_sourcemaps(
    client: AsyncHttpClient, state: _State, queue: assetmod.AssetQueue
) -> None:
    """Download and analyse referenced source maps."""
    pending = [url for url in state.sourcemap_urls if url]
    for _ in range(MAX_SOURCEMAP_DEPTH):
        if not pending:
            break
        batch = pending[:40]
        pending = pending[40:]
        results = await client.get_many(batch)
        for url, result in zip(batch, results, strict=True):
            if not result.ok:
                state.record_error(url, result)
                continue
            endpoints, parsed = sourcemap.analyze(
                result.text, result.url, state.context(result.url, SourceKind.SOURCEMAP)
            )
            state.collector.extend(endpoints)
            if parsed is not None:
                state.stats.sourcemaps += 1
                for original in sourcemap.original_source_urls(parsed)[:30]:
                    queue.push(original, result.url)

    # Original sources revealed by the maps still need analysing.
    if queue.has_pending:
        downloaded = await assetmod.download(client, queue.drain())
        for url, result, kind in downloaded:
            if result.ok and assetmod.is_textual(result):
                state.stats.assets_downloaded += 1
                await _analyse_document(state, queue, result, kind)
            elif not result.ok:
                state.record_error(url, result)


def select_render_targets(target: str, candidates: list[tuple[str, int]], limit: int) -> list[str]:
    """Choose which crawled pages are worth rendering in the browser.

    XHR traffic is per page: the requests a ski-report page fires are simply not
    fired by the home page. Rendering only the entry point therefore misses
    whatever the rest of the application does. The entry page always comes first;
    the others are ranked by how much script they pull in, because XHR traffic
    follows the JavaScript.

    Args:
        target: The scan target, always rendered.
        candidates: ``(url, script_count)`` pairs collected while crawling.
        limit: Maximum number of pages to render.

    Returns:
        Up to ``limit`` page URLs, entry page first.
    """
    ordered = [target]
    ranked = sorted(
        (item for item in candidates if item[0] != target), key=lambda item: (-item[1], item[0])
    )
    for url, _ in ranked:
        if len(ordered) >= limit:
            break
        if url not in ordered:
            ordered.append(url)
    return ordered


async def _stage_browser(
    state: _State, queue: assetmod.AssetQueue, client: AsyncHttpClient
) -> None:
    """Render the selected pages and turn observed traffic into endpoints."""
    if not state.settings.render:
        return

    budget = state.settings.render_pages
    targets = select_render_targets(state.target, state.page_candidates, budget)
    rendered: set[str] = set()

    # Two rounds: the first renders what the link crawler found, the second the
    # client side routes that only became visible once the app was running. In a
    # single page application the crawler finds exactly one page, so without the
    # second round the whole application beyond the entry route stays invisible.
    for _round in range(2):
        if not targets:
            break
        captures = await browsermod.capture_many(targets, state.settings)
        rendered.update(targets)
        for capture in captures:
            if capture.error:
                state.errors.append(
                    ScanError(
                        url=capture.final_url or state.target,
                        category="browser",
                        message=capture.error,
                    )
                )
            if capture.available:
                state.rendered_pages += 1
                _absorb_capture(state, queue, capture)

        remaining = budget - len(rendered)
        if remaining <= 0:
            break
        targets = [route for route in _spa_render_candidates(state) if route not in rendered][
            :remaining
        ]

    # Scripts injected at runtime were only discovered now; analyse them too.
    if queue.has_pending:
        downloaded = await assetmod.download(client, queue.drain())
        for url, result, kind in downloaded:
            if result.ok and assetmod.is_textual(result):
                state.stats.assets_downloaded += 1
                if kind == "js":
                    state.stats.scripts += 1
                await _analyse_document(state, queue, result, kind)
            elif not result.ok:
                state.record_error(url, result)


def _spa_render_candidates(state: _State) -> list[str]:
    """Routes worth rendering after the application has booted once.

    Args:
        state: Current scan state.

    Returns:
        In-scope, filter-approved route URLs.
    """
    candidates: list[str] = []
    for route in state.spa_routes:
        if not urlutil.host_allowed(
            route, state.settings.host_suffixes, state.settings.exclude_host_suffixes
        ):
            continue
        if not urlutil.matches_filters(
            route, state.settings.include_patterns, state.settings.exclude_patterns
        ):
            continue
        candidates.append(route)
    return candidates


def _absorb_capture(
    state: _State, queue: assetmod.AssetQueue, capture: browsermod.BrowserCapture
) -> None:
    """Fold one rendered page's observations into the shared state."""
    page_url = capture.final_url or state.target
    state.stats.requests += len(capture.requests)
    state.technologies.update(capture.frameworks)
    if capture.title and not state.page_title:
        state.page_title = capture.title

    for request in capture.requests:
        normalised = urlutil.normalize(request.url)
        if not normalised:
            continue
        # A challenged page makes the protection layer's own beacons the loudest
        # traffic on the wire; none of it belongs to the target's API.
        if urlutil.is_infrastructure_path(normalised):
            continue
        if not urlutil.matches_filters(
            normalised, state.settings.include_patterns, state.settings.exclude_patterns
        ):
            continue
        # Scripts injected at runtime never appear in the served HTML, so they
        # must be queued before any classification based skipping happens.
        if request.resource_type == "script":
            queue.push(normalised, page_url)

        is_api = (
            request.resource_type in browsermod.API_RESOURCE_TYPES
            or "json" in (request.content_type or "")
            or request.method not in {"GET", "HEAD"}
        )
        etype = classify(normalised, hint=request.resource_type, body_type=request.content_type)
        if etype is EndpointType.UNKNOWN and not is_api:
            continue
        try:
            method = HttpMethod(request.method.upper())
        except ValueError:
            method = HttpMethod.GET
        state.collector.add(
            Endpoint(
                url=normalised,
                method=method,
                method_observed=True,
                type=EndpointType.REST if etype is EndpointType.UNKNOWN else etype,
                source=SourceKind.NETWORK,
                source_url=page_url,
                evidence=f"{request.resource_type} {request.method} -> {request.status or request.failure}",
                confidence=Confidence.HIGH,
                status_code=request.status,
                content_type=request.content_type or None,
                params=request.post_keys,
                tags=["observed", f"resource:{request.resource_type}"],
            )
        )

    for socket_url in capture.websockets:
        state.collector.add(websocket.from_browser(socket_url, page_url))

    for worker_url in capture.service_workers:
        queue.push(worker_url, page_url, force=True)
        state.collector.add(
            Endpoint(
                url=worker_url,
                type=EndpointType.UNKNOWN,
                source=SourceKind.SERVICE_WORKER,
                source_url=page_url,
                evidence="registered service worker",
                confidence=Confidence.HIGH,
                tags=["service-worker"],
            )
        )

    if capture.cookies:
        state.collector.extend(metadata.parse_cookies(capture.cookies, page_url))

    for stored in capture.storage_urls:
        endpoint = jsmod.endpoint_from_url(
            stored, SourceKind.JAVASCRIPT, page_url, "web storage value"
        )
        if endpoint and endpoint.type is not EndpointType.UNKNOWN:
            endpoint.confidence = Confidence.LOW
            endpoint.tags = ["storage"]
            state.collector.add(endpoint)

    if capture.html:
        page = htmlmod.parse(capture.html, page_url)
        state.technologies.update(htmlmod.detect_technologies(page))
        _absorb_forms(state, page.forms, page.url)
        queue.push_many(page.scripts, page.url)
        # Anchors in a client rendered app exist only after the framework has run,
        # so the rendered DOM is the only place they can be harvested from.
        for link in page.anchors:
            if (
                urlutil.is_html_like(link)
                and link not in state.spa_routes
                and urlutil.same_scope(
                    link, state.target, follow_subdomains=state.settings.follow_subdomains
                )
            ):
                state.remember(state.spa_routes, link, limit=200)
        for url in [*page.data_urls, *page.media, *page.links]:
            _add_resource_endpoint(state, url, page.url)
        if page.inline_scripts:
            analysis = jsmod.analyze_inline_scripts(
                page.inline_scripts, page.url, state.context(page.url, SourceKind.INLINE_SCRIPT)
            )
            _absorb(state, analysis, queue)

    for error in capture.console_errors[:20]:
        state.errors.append(ScanError(url=page_url, category="javascript", message=error))


async def _stage_schemas(client: AsyncHttpClient, state: _State) -> None:
    """Fetch and expand referenced schema and service description documents."""
    if not state.settings.probe:
        return

    targets: list[tuple[str, str]] = []
    for url in state.schema_urls:
        targets.append((url, "openapi"))
        if "swagger-ui" in url.lower() or url.lower().rstrip("/").endswith(
            ("/api-docs", "/swagger")
        ):
            targets.extend((candidate, "openapi") for candidate in swagger.candidate_documents(url))
    for url in state.arcgis_services:
        targets.append((arcgis.metadata_url(url), "arcgis"))
    for url in state.ogc_services:
        service = geoserver.detect_service(url) or "WMS"
        targets.append((geoserver.capabilities_url(url, service), "ogc"))
    for url in state.graphql_urls:
        endpoint = graphql.make_endpoint(
            url, SourceKind.JAVASCRIPT, state.target, "graphql reference"
        )
        state.collector.add(endpoint)

    if state.settings.guess_schemas:
        origin = _origin(state.target)
        targets.extend((f"{origin}{path}", "openapi") for path in SCHEMA_PROBE_PATHS)

    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for url, kind in targets:
        if url not in seen:
            seen.add(url)
            unique.append((url, kind))
    if not unique:
        return

    results = await client.get_many([url for url, _ in unique])
    for (url, kind), result in zip(unique, results, strict=True):
        if not result.ok:
            if result.error and result.error.value not in {"http_404", "http_403"}:
                state.record_error(url, result)
            continue
        if kind == "openapi":
            expanded = swagger.analyze(result.text, result.url, result.content_type)
            if expanded:
                state.collector.extend(expanded)
                state.collector.add(
                    Endpoint(
                        url=result.url,
                        type=EndpointType.SWAGGER,
                        source=SourceKind.SWAGGER,
                        source_url=state.target,
                        evidence=f"OpenAPI document with {len(expanded)} operations",
                        confidence=Confidence.HIGH,
                    )
                )
        elif kind == "arcgis":
            state.collector.extend(arcgis.parse_catalog(result.text, result.url))
        elif kind == "ogc":
            state.collector.extend(geoserver.parse_capabilities(result.text, result.url))


def _select_endpoints(state: _State) -> tuple[list[Endpoint], list[str]]:
    """Apply every post-processing filter and return the final endpoints + routes."""
    endpoints = state.collector.sorted()
    endpoints = apimod.enrich(endpoints)
    endpoints = apimod.apply_filters(
        endpoints, state.settings.include_patterns, state.settings.exclude_patterns
    )
    endpoints = apimod.filter_by_host(
        endpoints, state.settings.host_suffixes, state.settings.exclude_host_suffixes
    )
    endpoints = apimod.prefer_observed_methods(endpoints)
    endpoints = apimod.filter_by_confidence(endpoints, state.settings.min_confidence)
    if not state.settings.keep_unknown:
        endpoints = apimod.drop_unknown(endpoints)
    endpoints, routes = apimod.split_routes(endpoints, _spa_render_candidates(state))
    return apimod.rank(endpoints), routes


def _finalise(
    state: _State,
    endpoints: list[Endpoint],
    routes: list[str],
    pages: int,
    queue: assetmod.AssetQueue,
    started: float,
) -> ScanResult:
    """Build the final result object from the selected endpoints."""
    state.stats.pages = pages
    state.stats.duration_seconds = round(time.perf_counter() - started, 2)

    return ScanResult(
        target=state.target,
        page_title=state.page_title or None,
        stats=state.stats,
        endpoints=endpoints,
        assets=queue.records,
        errors=state.errors,
        technologies=sorted(state.technologies),
        routes=routes,
        protection=state.protection,
        challenges=state.challenges,
    )
