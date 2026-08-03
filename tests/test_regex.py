"""Tests for the static extraction rule library."""

from __future__ import annotations

from endpoint_finder.discovery import regex as rules
from endpoint_finder.models import Confidence, HttpMethod

SAMPLE = """
const API_URL = "https://api.example.com/v2";
const baseURL = 'https://backend.example.com';
fetch("/api/v1/users");
fetch("/api/v1/users", { method: "POST", body: b });
axios.put("/api/v1/users/9", data);
axios({ url: "/api/orders", method: "delete" });
const xhr = new XMLHttpRequest();
xhr.open("PATCH", "/api/v1/profile");
$.ajax({ url: "/legacy/ajax/get", type: "POST" });
$.getJSON("/data/points.json");
navigator.sendBeacon("/collect");
new WebSocket("wss://live.example.com/ws");
new EventSource("/api/stream/events");
navigator.serviceWorker.register("/sw.js");
const tiles = "https://tiles.example.com/{z}/{x}/{y}.pbf";
const svc = "https://gis.example.com/arcgis/rest/services/Base/MapServer";
const wms = "https://geo.example.com/geoserver/ows?service=WMS&request=GetCapabilities";
const spec = "/swagger/v1/swagger.json";
const gqlEndpoint = "/graphql";
//# sourceMappingURL=app.js.map
"""


def _values(matches: list[rules.RawMatch]) -> set[str]:
    return {match.value for match in matches}


def test_call_sites_capture_urls_and_methods() -> None:
    matches = list(rules.iter_call_sites(SAMPLE))
    values = _values(matches)
    assert "/api/v1/users" in values
    assert "/api/v1/users/9" in values
    assert "/api/orders" in values
    assert "/api/v1/profile" in values
    assert "/legacy/ajax/get" in values
    assert "/data/points.json" in values
    assert "/collect" in values
    assert "/api/stream/events" in values
    assert "/sw.js" in values

    by_value = {match.value: match for match in matches}
    assert by_value["/api/v1/users/9"].method is HttpMethod.PUT
    assert by_value["/api/v1/profile"].method is HttpMethod.PATCH
    assert by_value["/api/orders"].method is HttpMethod.DELETE
    assert by_value["/collect"].method is HttpMethod.POST
    assert by_value["/legacy/ajax/get"].method is HttpMethod.POST
    assert all(match.confidence is Confidence.HIGH for match in matches if match.rule == "fetch")


def test_fetch_with_method_option() -> None:
    matches = [m for m in rules.iter_call_sites(SAMPLE) if m.value == "/api/v1/users"]
    assert HttpMethod.POST in {match.method for match in matches}


def test_config_values() -> None:
    values = _values(list(rules.iter_config_values(SAMPLE)))
    assert "https://api.example.com/v2" in values
    assert "https://backend.example.com" in values


def test_websockets() -> None:
    assert "wss://live.example.com/ws" in _values(list(rules.iter_websockets(SAMPLE)))


def test_service_urls() -> None:
    values = _values(list(rules.iter_service_urls(SAMPLE)))
    assert any("MapServer" in value for value in values)
    assert any("geoserver" in value for value in values)
    assert any("swagger.json" in value for value in values)
    assert any(value.endswith("/graphql") for value in values)


def test_generic_urls_find_tiles_and_data_files() -> None:
    values = _values(list(rules.iter_generic_urls(SAMPLE)))
    assert any("{z}/{x}/{y}.pbf" in value for value in values)
    assert any(value.endswith("points.json") for value in values)


def test_find_sourcemap() -> None:
    assert rules.find_sourcemap(SAMPLE) == "app.js.map"
    assert rules.find_sourcemap("no map here") is None


def test_extract_all_is_ordered_high_precision_first() -> None:
    matches = rules.extract_all(SAMPLE)
    assert matches
    assert matches[0].confidence is Confidence.HIGH


COMMENTED = """
// see http://api.jquery.com/data/ for details
/* @see https://docs.angularjs.org/api/ng.$sce
   also https://en.wikipedia.org/wiki/JSON */
const live = "https://api.example.com/v1/live";
fetch("/api/v1/real");
const s = "https://not-a-comment.example.com/a"; // trailing note http://noise.example.com/x
"""


def test_comment_spans_ignore_urls_inside_strings() -> None:
    spans = rules.comment_spans(COMMENTED)
    # The "//" of https:// inside the quoted strings must not open a comment.
    assert not rules.in_comment(spans, COMMENTED.index("https://api.example.com"))
    assert not rules.in_comment(spans, COMMENTED.index("https://not-a-comment"))
    assert rules.in_comment(spans, COMMENTED.index("http://api.jquery.com"))
    assert rules.in_comment(spans, COMMENTED.index("https://docs.angularjs.org"))
    assert rules.in_comment(spans, COMMENTED.index("http://noise.example.com"))


def test_extract_all_can_skip_comments() -> None:
    kept = {m.value for m in rules.extract_all(COMMENTED, skip_comments=True)}
    dropped = {m.value for m in rules.extract_all(COMMENTED)}

    assert any("api.example.com/v1/live" in v for v in kept)
    assert "/api/v1/real" in kept
    assert not any("api.jquery.com" in v for v in kept)
    assert not any("angularjs.org" in v for v in kept)
    assert not any("wikipedia.org" in v for v in kept)
    # Without the flag the documentation links are still returned.
    assert any("api.jquery.com" in v for v in dropped)


def test_graphql_operations_pattern() -> None:
    source = "const Q = gql`query GetUser($id: ID!) { user(id:$id){ name } }`;"
    found = rules.GRAPHQL_TAG.findall(source)
    assert found == [("query", "GetUser")]
