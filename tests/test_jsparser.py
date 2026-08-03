"""Tests for JavaScript analysis and endpoint resolution."""

from __future__ import annotations

from endpoint_finder.crawler.javascript import analyze_asset
from endpoint_finder.discovery import fetch as fetchmod
from endpoint_finder.discovery import xhr as xhrmod
from endpoint_finder.models import EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser.jsparser import (
    AnalysisContext,
    analyze_text,
    collect_base_urls,
    extract_concatenations,
    find_sourcemap_url,
)

BUNDLE = """
const API_BASE = "https://api.example.com";
fetch("/api/v1/users").then(r => r.json());
axios.post("/api/v1/orders", payload);
var u = "/legacy/getData.json";
xhr.open("GET", u);
new WebSocket("wss://live.example.com/feed");
const doc = "/openapi.json";
const gis = "https://gis.example.com/arcgis/rest/services/City/MapServer/2/query";
//# sourceMappingURL=/static/app.js.map
"""


def test_collect_base_urls(ctx: AnalysisContext) -> None:
    # Base URLs come back normalised, so the origin carries an explicit root path.
    assert "https://api.example.com/" in collect_base_urls(BUNDLE)


def test_analyze_text_resolves_relative_and_alternate_bases(ctx: AnalysisContext) -> None:
    endpoints = analyze_text(BUNDLE, ctx, extra_bases=["https://api.example.com"])
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://example.com/api/v1/users" in urls
    assert "https://api.example.com/api/v1/users" in urls


def test_fetch_module_extracts_methods(ctx: AnalysisContext) -> None:
    endpoints = fetchmod.extract(BUNDLE, ctx)
    users = [e for e in endpoints if e.url.endswith("/api/v1/users")]
    assert users
    assert users[0].source is SourceKind.JAVASCRIPT


def test_xhr_resolves_variable_targets(ctx: AnalysisContext) -> None:
    endpoints = xhrmod.extract(BUNDLE, ctx)
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://example.com/legacy/getData.json" in urls
    assert any("var:u" in endpoint.tags for endpoint in endpoints)


def test_sourcemap_reference_is_absolute(ctx: AnalysisContext) -> None:
    assert find_sourcemap_url(BUNDLE, ctx.source_url) == "https://example.com/static/app.js.map"


def test_analyze_asset_collects_follow_ups(ctx: AnalysisContext) -> None:
    analysis = analyze_asset(BUNDLE, ctx)
    assert analysis.sourcemap_url == "https://example.com/static/app.js.map"
    assert "https://api.example.com/" in analysis.base_urls
    assert any("openapi.json" in url for url in analysis.schema_urls)
    assert any("MapServer" in url for url in analysis.service_urls)

    types = {endpoint.type for endpoint in analysis.endpoints}
    assert EndpointType.REST in types
    assert EndpointType.WEBSOCKET in types
    assert EndpointType.ARCGIS in types

    ws = [e for e in analysis.endpoints if e.type is EndpointType.WEBSOCKET]
    assert ws[0].url == "wss://live.example.com/feed"
    assert ws[0].method is HttpMethod.ANY

    arcgis = [e for e in analysis.endpoints if e.type is EndpointType.ARCGIS]
    assert any(e.url.endswith("/MapServer") for e in arcgis)


def test_minified_regex_literals_do_not_become_endpoints(ctx: AnalysisContext) -> None:
    # Verbatim shape of the jQuery source that polluted a real scan.
    minified = (
        'a=/\\\\(?:["\\\\\\\\\\\\/bfnrt]|u[\\\\da-fA-F]{4})/g;'
        "n.parseJSON=function(b){if(a.JSON&&a.JSON.parse)return a.JSON.parse(b+'')};"
    )
    urls = {endpoint.url for endpoint in analyze_text(minified, ctx)}
    assert not any("parseJSON" in url or "function" in url for url in urls)


def test_base_fanout_is_bounded_and_marked(ctx: AnalysisContext) -> None:
    source = 'fetch("/api/v1/items");'
    bases = [f"https://host{n}.example.com" for n in range(6)]
    endpoints = analyze_text(source, ctx, extra_bases=bases)

    inferred = [e for e in endpoints if "base:inferred" in e.tags]
    assert len(inferred) <= 2, "speculative host guesses must stay bounded"
    assert all(e.confidence.value == "medium" for e in inferred)
    assert all(not e.method_observed for e in inferred)
    # The resolution against the file's own origin is never speculative.
    primary = [e for e in endpoints if e.url.startswith("https://example.com/")]
    assert primary and "base:inferred" not in primary[0].tags


def test_low_confidence_paths_are_not_fanned_out(ctx: AnalysisContext) -> None:
    # A bare quoted path is not proof of a request, so it stays on its own origin.
    endpoints = analyze_text('var p = "/api/loose/path";', ctx, extra_bases=["https://other.com"])
    assert not any(e.url.startswith("https://other.com") for e in endpoints)


CONCAT_SOURCE = """
var serviceUrl = "https://servis.example.com/web";
var other = "not a url";
CallServiceFactory.getData(serviceUrl + "/merkezler/iller");
CallServiceFactory.getData(serviceUrl + "/ucdegerler?merkezid=" + id + "&ay=" + m);
$scope.load = function (il) {
  CallServiceFactory.getData(serviceUrl + "/merkezler/ililcesi?il=" + convert(il));
};
CallServiceFactory.getData(other + "/should/not/resolve");
CallServiceFactory.getData(unknownVar + "/also/not/resolved");
// commented out: serviceUrl + "/dead/path"
"""


def test_concatenated_paths_are_rebuilt(ctx: AnalysisContext) -> None:
    endpoints = extract_concatenations(CONCAT_SOURCE, ctx)
    urls = {endpoint.url for endpoint in endpoints}

    assert "https://servis.example.com/web/merkezler/iller" in urls
    assert "https://servis.example.com/web/ucdegerler?merkezid=" in urls
    assert "https://servis.example.com/web/merkezler/ililcesi?il=" in urls
    # The base path of the variable must be preserved: urljoin would drop "/web".
    assert all("/web/" in url for url in urls)


def test_concatenation_requires_a_resolvable_absolute_base(ctx: AnalysisContext) -> None:
    urls = {e.url for e in extract_concatenations(CONCAT_SOURCE, ctx)}
    assert not any("should/not/resolve" in url for url in urls)
    assert not any("also/not/resolved" in url for url in urls)


def test_concatenation_ignores_comments(ctx: AnalysisContext) -> None:
    urls = {e.url for e in extract_concatenations(CONCAT_SOURCE, ctx)}
    assert not any("dead/path" in url for url in urls)


def test_concatenation_is_high_confidence_and_tagged(ctx: AnalysisContext) -> None:
    endpoints = extract_concatenations(CONCAT_SOURCE, ctx)
    assert endpoints
    assert all(e.confidence.value == "high" for e in endpoints)
    assert all("rule:concat" in e.tags for e in endpoints)
    assert all("base:serviceUrl" in e.tags for e in endpoints)


def test_resolve_string_variable_forms() -> None:
    from endpoint_finder.parser.jsparser import resolve_string_variable as resolve

    assert resolve('var a = "https://x.com";', "a") == "https://x.com"
    assert resolve('this.apiRoot = "https://y.com/api";', "this.apiRoot") == "https://y.com/api"
    assert resolve('$scope.svc = "https://z.com";', "$scope.svc") == "https://z.com"
    assert resolve('{ base: "https://w.com" }', "base") == "https://w.com"
    # The last assignment wins.
    assert resolve('var a = "https://one.com";\na = "https://two.com";', "a") == "https://two.com"
    assert resolve("var a = compute();", "a") is None


def test_ooxml_archive_internals_are_not_endpoints(ctx: AnalysisContext) -> None:
    # Shape of the string table a SheetJS/exceljs bundle carries.
    bundle = """
    var parts = ["/xl/workbook.xml", "/xl/sharedStrings.xml", "/xl/styles.xml",
                 "/_rels/.rels", "/docProps/app.xml", "/docProps/core.xml",
                 "/xl/theme/theme1.xml", "/word/document.xml", "/word/persons/person.xml",
                 "/[Content_Types].xml", "/META-INF/manifest.xml", "/content.xml"];
    fetch("/api/v1/export");
    """
    urls = {endpoint.url for endpoint in analyze_text(bundle, ctx)}
    for fragment in (
        "workbook.xml",
        "sharedStrings.xml",
        "styles.xml",
        "_rels",
        "docProps",
        "theme1.xml",
        "document.xml",
        "person.xml",
        "Content_Types",
        "manifest.xml",
    ):
        assert not any(fragment.lower() in url.lower() for url in urls), fragment
    # A genuine endpoint in the same file is unaffected.
    assert "https://example.com/api/v1/export" in urls


def test_real_xml_endpoints_still_survive(ctx: AnalysisContext) -> None:
    source = 'fetch("/api/data/export.xml"); var s = "/sitemap.xml"; var f = "/feeds/news.xml";'
    urls = {endpoint.url for endpoint in analyze_text(source, ctx)}
    assert "https://example.com/api/data/export.xml" in urls
    assert "https://example.com/sitemap.xml" in urls


def test_spa_routes_are_recovered_from_router_config(ctx: AnalysisContext) -> None:
    from endpoint_finder.parser.jsparser import extract_spa_routes

    bundle = """
    const routes = [
      {path: '', redirectTo: 'home-page', pathMatch: 'full'},
      {path: 'home-page', component: HomeComponent},
      {path: 'event-catalog', component: CatalogComponent},
      {path: 'earthquake/detail/:id', component: DetailComponent},
      {path: '**', component: NotFoundComponent},
    ];
    <Route path="/last-earthquakes" element={<List/>} />
    const svg = {path: 'M12 2L2 7l10 5'};
    const asset = {path: 'assets/img/logo.svg'};
    """
    routes = extract_spa_routes(bundle, "https://app.example.com/")

    assert "https://app.example.com/home-page" in routes
    assert "https://app.example.com/event-catalog" in routes
    assert "https://app.example.com/last-earthquakes" in routes
    # Parameterised, wildcard, empty and asset paths are not navigable routes.
    assert not any(":id" in r for r in routes)
    assert not any("*" in r for r in routes)
    assert not any(".svg" in r for r in routes)
    # SVG path data contains spaces so it never matches in the first place.
    assert not any("M12" in r for r in routes)


def test_spa_routes_are_deduplicated_and_bounded(ctx: AnalysisContext) -> None:
    from endpoint_finder.parser.jsparser import extract_spa_routes

    bundle = "".join(f"{{path: 'route{n}'}}," for n in range(300))
    routes = extract_spa_routes(bundle, "https://app.example.com/", limit=25)
    assert len(routes) == 25
    assert len(set(routes)) == 25


def test_analyze_asset_exposes_spa_routes(ctx: AnalysisContext) -> None:
    analysis = analyze_asset("const r=[{path:'event-catalog'}];", ctx)
    assert any(url.endswith("/event-catalog") for url in analysis.spa_routes)


def test_noise_is_filtered(ctx: AnalysisContext) -> None:
    noisy = """
    // Licensed under MIT, see https://opensource.org/licenses/MIT
    const schema = "http://www.w3.org/2000/svg";
    const logo = "/assets/logo.png";
    """
    urls = {endpoint.url for endpoint in analyze_text(noisy, ctx)}
    assert not any("w3.org" in url for url in urls)
    assert not any(url.endswith(".png") for url in urls)


def test_graphql_operations_are_attached(ctx: AnalysisContext) -> None:
    source = 'const Q = gql`query GetUser { user { id } }`; const url = "/graphql";'
    analysis = analyze_asset(source, ctx)
    graphql_endpoints = [e for e in analysis.endpoints if e.type is EndpointType.GRAPHQL]
    assert graphql_endpoints
    assert any("query:GetUser" in endpoint.tags for endpoint in graphql_endpoints)
    assert graphql_endpoints[0].method is HttpMethod.POST
