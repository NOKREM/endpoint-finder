"""Tests for endpoint classification and method inference."""

from __future__ import annotations

import pytest

from endpoint_finder.discovery.classifier import classify, guess_method, interest_score
from endpoint_finder.models import EndpointType, HttpMethod


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.com/api/v1/users", EndpointType.REST),
        ("https://x.com/rest/orders", EndpointType.REST),
        ("https://x.com/v2/items", EndpointType.REST),
        ("https://x.com/graphql", EndpointType.GRAPHQL),
        ("https://x.com/api/graphql", EndpointType.GRAPHQL),
        ("https://x.com/arcgis/rest/services/A/MapServer", EndpointType.ARCGIS),
        ("https://x.com/arcgis/rest/services/A/FeatureServer/0/query", EndpointType.ARCGIS),
        ("https://x.com/arcgis/rest/services/A/ImageServer", EndpointType.IMAGE_SERVICE),
        ("https://x.com/arcgis/rest/services/A/VectorTileServer", EndpointType.TILE_SERVER),
        ("https://x.com/geoserver/ows?service=WFS&request=GetCapabilities", EndpointType.GEOSERVER),
        ("https://x.com/geoserver/wms", EndpointType.GEOSERVER),
        ("https://x.com/gs/service?SERVICE=WMTS&REQUEST=GetTile", EndpointType.TILE_SERVER),
        ("https://x.com/tiles/{z}/{x}/{y}.pbf", EndpointType.TILE_SERVER),
        ("https://x.com/login", EndpointType.AUTH),
        ("https://x.com/oauth2/token", EndpointType.AUTH),
        ("wss://x.com/socket", EndpointType.WEBSOCKET),
        ("https://x.com/swagger.json", EndpointType.SWAGGER),
        ("https://x.com/v3/api-docs", EndpointType.SWAGGER),
        ("https://x.com/data/cities.geojson", EndpointType.STATIC_JSON),
        ("https://x.com/service.wsdl", EndpointType.SOAP),
        ("https://x.com/api/stream/events", EndpointType.STREAM),
        ("https://x.com/about-us", EndpointType.UNKNOWN),
    ],
)
def test_classify(url: str, expected: EndpointType) -> None:
    assert classify(url) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # Markers must match a whole path segment, not a substring.
        ("https://x.com/App_Themes/mgm/reset.css", EndpointType.UNKNOWN),
        ("https://x.com/js/events_mouse.html", EndpointType.UNKNOWN),
        ("https://x.com/authors/kim", EndpointType.UNKNOWN),
        ("https://x.com/tokenizer.js", EndpointType.UNKNOWN),
        ("https://x.com/streams-guide.html", EndpointType.UNKNOWN),
        # ... while genuine segments still classify.
        ("https://x.com/account/reset", EndpointType.AUTH),
        # A collection named "events" is a REST resource, not an SSE stream.
        ("https://x.com/api/events", EndpointType.REST),
        ("https://x.com/api/events/stream", EndpointType.STREAM),
        ("https://x.com/auth/token?next=/", EndpointType.AUTH),
    ],
)
def test_markers_require_segment_boundaries(url: str, expected: EndpointType) -> None:
    assert classify(url) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # Version glued to the word - AFAD's public API is served from /apiv2/.
        ("https://x.com/apiv2/event/filter?minmag=5", EndpointType.REST),
        ("https://x.com/api2/events", EndpointType.REST),
        ("https://x.com/api_v3/events", EndpointType.REST),
        ("https://x.com/apis/events", EndpointType.REST),
        ("https://x.com/api", EndpointType.REST),
        ("https://x.com/api?q=1", EndpointType.REST),
        # ... but ordinary words that merely start with "api" are not APIs.
        ("https://x.com/apiary/bees", EndpointType.UNKNOWN),
        ("https://x.com/apiculture", EndpointType.UNKNOWN),
    ],
)
def test_api_prefix_variants(url: str, expected: EndpointType) -> None:
    assert classify(url) == expected


def test_classify_uses_content_type_hint() -> None:
    assert classify("https://x.com/thing", body_type="application/json") is EndpointType.REST


def test_guess_method() -> None:
    assert guess_method("https://x.com/graphql", EndpointType.GRAPHQL) is HttpMethod.POST
    assert guess_method("https://x.com/login", EndpointType.AUTH) is HttpMethod.POST
    assert guess_method("https://x.com/api/items", EndpointType.REST) is HttpMethod.GET
    assert guess_method("https://x.com/api/items/create", EndpointType.REST) is HttpMethod.POST
    assert guess_method("wss://x.com/ws", EndpointType.WEBSOCKET) is HttpMethod.ANY


def test_explicit_get_is_not_overridden_by_a_guess() -> None:
    # "/save" would normally be guessed as POST; a call site that proved GET wins.
    assert (
        guess_method("https://x.com/api/items/save", EndpointType.REST, HttpMethod.GET)
        is HttpMethod.GET
    )
    assert guess_method("https://x.com/api/items/save", EndpointType.REST) is HttpMethod.POST


def test_websocket_type_forces_any_method() -> None:
    assert guess_method("wss://x.com/ws", EndpointType.WEBSOCKET, HttpMethod.GET) is HttpMethod.ANY


def test_observed_method_wins() -> None:
    assert (
        guess_method("https://x.com/api/items", EndpointType.REST, HttpMethod.DELETE)
        is HttpMethod.DELETE
    )


def test_interest_score_ordering() -> None:
    assert interest_score(EndpointType.GRAPHQL) > interest_score(EndpointType.REST)
    assert interest_score(EndpointType.REST) > interest_score(EndpointType.STATIC_JSON)
    assert interest_score(EndpointType.STATIC_JSON) > interest_score(EndpointType.UNKNOWN)
