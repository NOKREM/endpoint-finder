"""Analysis of a downloaded text asset: JavaScript, CSS, JSON or XML."""

from __future__ import annotations

from dataclasses import dataclass, field

from endpoint_finder.discovery import arcgis, fetch, geoserver, graphql, swagger, websocket, xhr
from endpoint_finder.discovery.classifier import classify
from endpoint_finder.models import Endpoint, EndpointType, SourceKind
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import (
    AnalysisContext,
    analyze_text,
    collect_base_urls,
    extract_concatenations,
    extract_spa_routes,
    find_sourcemap_url,
)


@dataclass(slots=True)
class AssetAnalysis:
    """Result of analysing one asset.

    Attributes:
        endpoints: Every endpoint discovered inside the asset.
        sourcemap_url: Absolute ``sourceMappingURL`` reference, if present.
        base_urls: Absolute base URLs declared in configuration constants.
        schema_urls: Swagger/OpenAPI documents referenced by the asset.
        service_urls: ArcGIS/OGC service roots that deserve a metadata fetch.
        graphql_urls: GraphQL endpoints referenced by the asset.
        spa_routes: Client side router paths declared in the asset.
    """

    endpoints: list[Endpoint] = field(default_factory=list)
    sourcemap_url: str | None = None
    base_urls: list[str] = field(default_factory=list)
    schema_urls: list[str] = field(default_factory=list)
    service_urls: list[str] = field(default_factory=list)
    graphql_urls: list[str] = field(default_factory=list)
    spa_routes: list[str] = field(default_factory=list)


def analyze_asset(
    text: str,
    ctx: AnalysisContext,
    *,
    extra_bases: list[str] | None = None,
    parse_sourcemap_reference: bool = True,
) -> AssetAnalysis:
    """Run every static analyser over one text asset.

    Args:
        text: Asset body.
        ctx: Resolution and filtering context.
        extra_bases: Base URLs harvested from previously analysed assets.
        parse_sourcemap_reference: Look for a trailing ``sourceMappingURL``.

    Returns:
        An :class:`AssetAnalysis` with endpoints and follow-up work items.
    """
    analysis = AssetAnalysis()
    if not text:
        return analysis

    analysis.base_urls = collect_base_urls(text)
    bases = [*(extra_bases or []), *analysis.base_urls]

    analysis.endpoints.extend(analyze_text(text, ctx, extra_bases=bases))
    analysis.endpoints.extend(extract_concatenations(text, ctx))
    analysis.endpoints.extend(fetch.extract(text, ctx, bases))
    analysis.endpoints.extend(xhr.extract(text, ctx))
    analysis.endpoints.extend(websocket.from_source(text, ctx))

    if parse_sourcemap_reference:
        analysis.sourcemap_url = find_sourcemap_url(text, ctx.source_url)

    analysis.spa_routes = extract_spa_routes(text, ctx.source_url)

    _derive_services(analysis, ctx)

    graphql_url = analysis.graphql_urls[0] if analysis.graphql_urls else None
    analysis.endpoints.extend(graphql.operations_from_source(text, ctx.source_url, graphql_url))
    return analysis


def _derive_services(analysis: AssetAnalysis, ctx: AnalysisContext) -> None:
    """Promote raw URLs into ArcGIS/OGC/Swagger/GraphQL service records."""
    extra: list[Endpoint] = []
    for endpoint in list(analysis.endpoints):
        url = endpoint.url

        service = arcgis.make_service_endpoint(
            url, ctx.source_kind, ctx.source_url, endpoint.evidence or ""
        )
        if service is not None:
            extra.append(service)
            if service.url not in analysis.service_urls:
                analysis.service_urls.append(service.url)
            continue

        ogc = geoserver.make_service_endpoint(
            url, ctx.source_kind, ctx.source_url, endpoint.evidence or ""
        )
        if ogc is not None:
            extra.append(ogc)
            if ogc.url not in analysis.service_urls:
                analysis.service_urls.append(ogc.url)
            continue

        if swagger.looks_like_swagger(url):
            endpoint.type = EndpointType.SWAGGER
            if url not in analysis.schema_urls:
                analysis.schema_urls.append(url)
            continue

        if graphql.is_graphql(url):
            endpoint.type = EndpointType.GRAPHQL
            if url not in analysis.graphql_urls:
                analysis.graphql_urls.append(url)
    analysis.endpoints.extend(extra)


def analyze_inline_scripts(
    scripts: list[str], page_url: str, ctx_template: AnalysisContext
) -> AssetAnalysis:
    """Analyse every inline ``<script>`` of a page as one virtual asset.

    Args:
        scripts: Bodies of the inline scripts.
        page_url: URL of the page they belong to.
        ctx_template: Context to clone; only the source kind is overridden.

    Returns:
        The combined analysis of all inline scripts.
    """
    ctx = AnalysisContext(
        source_url=page_url,
        source_kind=SourceKind.INLINE_SCRIPT,
        target=ctx_template.target,
        follow_subdomains=ctx_template.follow_subdomains,
        keep_external=ctx_template.keep_external,
        include=ctx_template.include,
        exclude=ctx_template.exclude,
    )
    combined = "\n;\n".join(scripts)
    return analyze_asset(combined, ctx, parse_sourcemap_reference=False)


def analyze_json_blobs(
    blobs: list[str], page_url: str, ctx_template: AnalysisContext
) -> AssetAnalysis:
    """Analyse embedded JSON payloads such as ``__NEXT_DATA__`` or JSON-LD.

    Args:
        blobs: Raw JSON bodies embedded in the page.
        page_url: URL of the page.
        ctx_template: Context to clone.

    Returns:
        The combined analysis of all JSON blobs.
    """
    ctx = AnalysisContext(
        source_url=page_url,
        source_kind=SourceKind.JSON,
        target=ctx_template.target,
        follow_subdomains=ctx_template.follow_subdomains,
        keep_external=ctx_template.keep_external,
        include=ctx_template.include,
        exclude=ctx_template.exclude,
    )
    return analyze_asset("\n".join(blobs), ctx, parse_sourcemap_reference=False)


def endpoint_from_url(
    url: str,
    source: SourceKind,
    source_url: str,
    evidence: str = "",
) -> Endpoint | None:
    """Build a classified endpoint from a bare URL.

    Args:
        url: Absolute URL.
        source: Where it was observed.
        source_url: Artefact it came from.
        evidence: Supporting snippet.

    Returns:
        The endpoint, or ``None`` when the URL cannot be normalised.
    """
    normalised = urlutil.normalize(url)
    if not normalised:
        return None
    return Endpoint(
        url=normalised,
        type=classify(normalised, hint=source.value),
        source=source,
        source_url=source_url,
        evidence=evidence,
    )
