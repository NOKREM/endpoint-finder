"""Rule based classification of endpoints into semantic categories."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from endpoint_finder.models import EndpointType, HttpMethod

_ARCGIS_MARKERS: tuple[tuple[str, EndpointType], ...] = (
    ("/imageserver", EndpointType.IMAGE_SERVICE),
    ("/vectortileserver", EndpointType.TILE_SERVER),
    ("/mapserver", EndpointType.ARCGIS),
    ("/featureserver", EndpointType.ARCGIS),
    ("/sceneserver", EndpointType.ARCGIS),
    ("/geometryserver", EndpointType.ARCGIS),
    ("/gpserver", EndpointType.ARCGIS),
    ("/geocodeserver", EndpointType.ARCGIS),
    ("/geodataserver", EndpointType.ARCGIS),
    ("/globeserver", EndpointType.ARCGIS),
    ("/streamserver", EndpointType.ARCGIS),
    ("/arcgis/rest/", EndpointType.ARCGIS),
)

_OGC_SERVICES = {"wms", "wmts", "wfs", "wcs", "csw", "wps"}
_OGC_PATH_MARKERS = ("/geoserver", "/ows", "/wms", "/wmts", "/wfs", "/wcs", "/mapserv", "/qgis")

#: Path *segments* that mark an authentication endpoint. Matching whole segments
#: rather than substrings keeps ``/App_Themes/reset.css`` out of this category.
_AUTH_SEGMENTS = (
    "login",
    "signin",
    "sign-in",
    "logout",
    "signout",
    "register",
    "signup",
    "oauth",
    "oauth2",
    "token",
    "authorize",
    "auth",
    "sso",
    "saml",
    "session",
    "password",
    "forgot",
    "reset",
    "verify",
    "otp",
    "mfa",
    "2fa",
    "refresh",
    "identity",
    "jwt",
    "openid-configuration",
    "connect",
)

_SWAGGER_MARKERS = (
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "/swagger-ui",
    "/swagger/",
    "/api-docs",
    "/apidocs",
    "/redoc",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi",
)

_GRAPHQL_MARKERS = ("/graphql", "/graphiql", "/gql", "/altair", "/playground", "/subscriptions")

#: Path segments that mark a streaming endpoint (same whole-segment rule as auth).
#: Deliberately narrow: ``events``, ``subscribe`` and ``notifications`` name an
#: ordinary REST collection far more often than a live stream, and classifying
#: ``/apiv2/events`` as SSE hides a plain API behind the wrong label.
_STREAM_SEGMENTS = ("sse", "stream", "streams", "eventsource", "event-stream", "livestream")

_TILE_MARKERS = ("{z}", "{x}", "{y}", "{-y}", "/tiles/", "/tile/", ".pbf", ".mvt", "/wmts")

#: ``/api/``, ``/apis/``, ``/apiv2/``, ``/api2/`` — the version suffix is glued to
#: the word often enough that a plain ``/api/`` substring test misses the endpoint
#: entirely. The trailing boundary keeps ``/apiary`` and ``/apiculture`` out.
_API_PREFIX = re.compile(r"/api(?:s|v\d{1,2}|_v\d{1,2}|\d{1,2})?(?:/|\?|$)", re.IGNORECASE)

_REST_MARKERS = (
    "/api/",
    "/api?",
    "/apis/",
    "/rest/",
    "/restapi",
    "/services/",
    "/service/",
    "/rpc/",
    "/ajax/",
    "/query",
    "/graph/",
    "/gateway/",
    "/backend/",
    "/data/",
)


def _segment_matcher(segments: tuple[str, ...]) -> re.Pattern[str]:
    """Compile a pattern matching any of ``segments`` as a whole path segment.

    Args:
        segments: Bare segment names, without slashes.

    Returns:
        A pattern that matches ``/<segment>`` followed by ``/``, ``?`` or the end
        of the path, so ``reset`` never matches inside ``reset.css``.
    """
    alternation = "|".join(re.escape(segment) for segment in segments)
    return re.compile(rf"(?:^|/)(?:{alternation})(?:[/?]|$)", re.IGNORECASE)


_AUTH_RE = _segment_matcher(_AUTH_SEGMENTS)
_STREAM_RE = _segment_matcher(_STREAM_SEGMENTS)

_VERSION_SEGMENT = re.compile(r"/v[1-9]\d?(?:/|$)")
_STATIC_DATA_EXT = (".json", ".geojson", ".topojson", ".xml", ".csv", ".yaml", ".yml")

_MUTATING_HINTS = (
    "create",
    "update",
    "delete",
    "remove",
    "insert",
    "add",
    "save",
    "submit",
    "upload",
    "edit",
    "modify",
    "post",
    "put",
    "patch",
    "send",
    "apply",
)


def classify(url: str, *, hint: str = "", body_type: str = "") -> EndpointType:
    """Classify an endpoint URL into an :class:`EndpointType`.

    The rules are ordered from most specific to most generic; the first match wins.

    Args:
        url: Absolute, normalised endpoint URL.
        hint: Optional extra context such as the extraction rule name.
        body_type: Optional response ``Content-Type`` observed for this URL.

    Returns:
        The best matching endpoint type.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    lowered_path = (parts.path or "").lower()
    lowered_query = (parts.query or "").lower()
    lowered = f"{lowered_path}?{lowered_query}" if lowered_query else lowered_path
    context = f"{hint} {body_type}".lower()

    if scheme in {"ws", "wss"}:
        return EndpointType.WEBSOCKET

    if any(marker in lowered for marker in _SWAGGER_MARKERS):
        return EndpointType.SWAGGER

    if any(marker in lowered_path for marker in _GRAPHQL_MARKERS) or "graphql" in context:
        return EndpointType.GRAPHQL

    for marker, etype in _ARCGIS_MARKERS:
        if marker in lowered_path:
            return etype

    query_params = parse_qs(lowered_query)
    service_values = {value.lower() for value in query_params.get("service", [])}
    if service_values & _OGC_SERVICES:
        if "wmts" in service_values:
            return EndpointType.TILE_SERVER
        return EndpointType.GEOSERVER
    if any(marker in lowered_path for marker in _OGC_PATH_MARKERS):
        if "wmts" in lowered_path:
            return EndpointType.TILE_SERVER
        return EndpointType.GEOSERVER
    if "getcapabilities" in lowered:
        return EndpointType.GEOSERVER

    if any(marker in lowered for marker in _TILE_MARKERS):
        return EndpointType.TILE_SERVER

    if _AUTH_RE.search(lowered_path):
        return EndpointType.AUTH

    if "wsdl" in lowered or "soap" in context:
        return EndpointType.SOAP

    if _STREAM_RE.search(lowered_path) or "eventsource" in context:
        return EndpointType.STREAM

    if (
        any(marker in lowered for marker in _REST_MARKERS)
        or _API_PREFIX.search(lowered_path)
        or _VERSION_SEGMENT.search(lowered_path)
    ):
        if lowered_path.endswith(_STATIC_DATA_EXT) and "/api" not in lowered_path:
            return EndpointType.STATIC_JSON
        return EndpointType.REST

    if lowered_path.endswith(_STATIC_DATA_EXT):
        return EndpointType.STATIC_JSON
    if body_type in {"application/json", "application/geo+json", "application/ld+json"}:
        return EndpointType.REST
    if body_type in {"text/xml", "application/xml"}:
        return EndpointType.STATIC_JSON

    return EndpointType.UNKNOWN


def guess_method(url: str, etype: EndpointType, observed: HttpMethod | None = None) -> HttpMethod:
    """Infer the most plausible HTTP verb for an endpoint.

    A verb that was actually observed at a call site or on the wire always wins;
    heuristics only fill the gap when ``observed`` is ``None``. Passing ``GET``
    explicitly therefore means "this really is a GET", not "nothing was seen",
    which keeps a guessed ``POST`` from shadowing a proven ``GET``.

    Args:
        url: Endpoint URL.
        etype: Classified endpoint type.
        observed: Verb captured at the call site or in the browser, if any.

    Returns:
        The inferred :class:`HttpMethod`.
    """
    if etype is EndpointType.WEBSOCKET:
        return HttpMethod.ANY
    if observed is not None:
        return observed
    lowered = urlsplit(url).path.lower()
    if etype is EndpointType.GRAPHQL:
        return HttpMethod.POST
    if etype is EndpointType.AUTH and re.search(
        r"(?:^|/)(?:login|token|signin|sign-in|register|signup)(?:[/?]|$)", lowered
    ):
        return HttpMethod.POST
    segments = [segment for segment in lowered.split("/") if segment]
    if segments and any(hint == segments[-1] for hint in _MUTATING_HINTS):
        return HttpMethod.POST
    return HttpMethod.GET


def is_documentation(etype: EndpointType) -> bool:
    """Whether the endpoint is a machine readable API description.

    Args:
        etype: Endpoint type to test.

    Returns:
        ``True`` for Swagger/OpenAPI documents.
    """
    return etype is EndpointType.SWAGGER


def interest_score(etype: EndpointType) -> int:
    """Rank endpoint types so reports can surface the interesting ones first.

    Args:
        etype: Endpoint type to rank.

    Returns:
        A score where higher means more interesting to an analyst.
    """
    ranking = {
        EndpointType.GRAPHQL: 100,
        EndpointType.SWAGGER: 95,
        EndpointType.AUTH: 90,
        EndpointType.REST: 85,
        EndpointType.ARCGIS: 80,
        EndpointType.GEOSERVER: 78,
        EndpointType.IMAGE_SERVICE: 70,
        EndpointType.WEBSOCKET: 68,
        EndpointType.SOAP: 60,
        EndpointType.STREAM: 58,
        EndpointType.TILE_SERVER: 40,
        EndpointType.STATIC_JSON: 30,
        EndpointType.UNKNOWN: 10,
    }
    return ranking.get(etype, 0)
