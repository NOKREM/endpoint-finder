"""The regular expression library that powers static endpoint extraction.

Every pattern yields :class:`RawMatch` objects carrying the matched value, an
optional HTTP verb, a confidence level and a short evidence snippet.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass

from endpoint_finder.models import Confidence, HttpMethod

#: Braces stay inside the body so ``/{z}/{x}/{y}`` and ``/api/${id}`` are captured whole.
_URL_BODY = r"[^\s'\"`<>\\|^\[\]]+"

# ---------------------------------------------------------------------------
# Core URL shapes
# ---------------------------------------------------------------------------
ABSOLUTE_URL = re.compile(rf"https?://{_URL_BODY}", re.IGNORECASE)
WEBSOCKET_URL = re.compile(rf"wss?://{_URL_BODY}", re.IGNORECASE)
PROTOCOL_RELATIVE_URL = re.compile(
    r"//[a-z0-9][a-z0-9.\-]*\.[a-z]{2,24}(?::\d{2,5})?/[^\s'\"`<>\\]*", re.IGNORECASE
)
QUOTED_PATH = re.compile(r"""['"`](/(?!/)[A-Za-z0-9_\-./~%:{}$][^\s'"`<>\\]{1,512}?)['"`]""")
API_PATH = re.compile(
    r"""(?<![\w.])/(?:api|apis|rest|restapi|service|services|ws|rpc|ajax|graphql|gql|"""
    r"""data|json|query|export|v\d{1,2})(?:/[^\s'"`<>\\)]*)?""",
    re.IGNORECASE,
)
VERSIONED_PATH = re.compile(r"""(?<![\w.])/v[1-9]\d?/[A-Za-z0-9_\-./~%]{1,256}""")

# ---------------------------------------------------------------------------
# AJAX call sites
# ---------------------------------------------------------------------------
FETCH_CALL = re.compile(r"""fetch\s*\(\s*['"`]([^'"`]{2,512})['"`]""")
FETCH_WITH_METHOD = re.compile(
    r"""fetch\s*\(\s*['"`]([^'"`]{2,512})['"`]\s*,\s*\{(?P<opts>[^{}]{0,400})""",
    re.DOTALL,
)
METHOD_IN_OPTIONS = re.compile(
    r"""method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]""", re.IGNORECASE
)
AXIOS_VERB = re.compile(
    r"""axios\s*\.\s*(get|post|put|patch|delete|head|options|request)\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
AXIOS_CONFIG = re.compile(r"""axios\s*\(\s*\{(?P<opts>[^{}]{0,600})\}""", re.DOTALL)
AXIOS_CREATE = re.compile(r"""axios\s*\.\s*create\s*\(\s*\{(?P<opts>[^{}]{0,600})\}""", re.DOTALL)
URL_IN_OPTIONS = re.compile(r"""\burl\s*:\s*['"`]([^'"`]{2,512})['"`]""")
BASEURL_IN_OPTIONS = re.compile(r"""\bbaseURL\s*:\s*['"`]([^'"`]{2,512})['"`]""")
XHR_OPEN = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)['"`]\s*,\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
XHR_OPEN_VAR = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]\s*,\s*([A-Za-z_$][\w$.]{0,60})\s*[,)]""",
    re.IGNORECASE,
)
JQUERY_AJAX = re.compile(
    r"""\$(?:\.\w+)?\s*\.\s*(ajax|get|post|getJSON|getScript|load)\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
JQUERY_AJAX_CONFIG = re.compile(r"""\$\s*\.\s*ajax\s*\(\s*\{(?P<opts>[^{}]{0,600})\}""", re.DOTALL)
ANGULAR_HTTP = re.compile(
    r"""\.(?:http)?(?:Client)?\s*\.\s*(get|post|put|patch|delete|head|options)\s*(?:<[^>()]{0,120}>)?\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
)
SUPERAGENT = re.compile(
    r"""(?:request|superagent)\s*\.\s*(get|post|put|patch|del|delete|head)\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
KY_WRETCH = re.compile(
    r"""(?:ky|wretch)\s*(?:\.\s*(get|post|put|patch|delete|head))?\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
#: ``serviceUrl + "/merkezler/iller"`` — the dominant way hand-written (non-bundled)
#: front ends build request URLs. The variable is resolved separately; without it
#: the path alone is indistinguishable from any other quoted string.
CONCAT_BASE = re.compile(
    r"""(?P<name>[A-Za-z_$][\w$.]{0,60})\s*\+\s*['"`](?P<path>/[^'"`\s]{1,300})['"`]"""
)

#: ``"/api/x" + someVar`` — the mirror image, where the path comes first.
CONCAT_SUFFIX = re.compile(
    r"""['"`](?P<path>/[^'"`\s]{2,300})['"`]\s*\+\s*(?P<name>[A-Za-z_$][\w$.]{0,60})"""
)

#: A plain ``name = "https://..."`` assignment, used to resolve the variables above.
STRING_ASSIGNMENT = (
    r"""(?:var|let|const)?\s*(?:this\.|self\.|window\.|\$scope\.)?{name}\s*[:=]\s*"""
    r"""['"`]([^'"`\n]{{2,400}})['"`]"""
)

#: Client side router configuration: ``{path: 'event-catalog', component: ...}``
#: for Angular/Vue, ``path="/event-catalog"`` for React Router. In a single page
#: application these are the only record of which routes exist - the server hands
#: back the same shell for every one of them.
SPA_ROUTE = re.compile(
    r"""(?<![\w$])(?:path|redirectTo)\s*[:=]\s*['"](?P<route>/?[A-Za-z0-9][A-Za-z0-9\-_/]{1,60})['"]"""
)

NAVIGATOR_BEACON = re.compile(r"""sendBeacon\s*\(\s*['"`]([^'"`]{2,512})['"`]""")
EVENT_SOURCE = re.compile(r"""new\s+EventSource\s*\(\s*['"`]([^'"`]{2,512})['"`]""")
WEBSOCKET_CTOR = re.compile(
    r"""new\s+(?:WebSocket|SockJS|ReconnectingWebSocket)\s*\(\s*['"`]([^'"`]{2,512})['"`]""",
    re.IGNORECASE,
)
IMPORT_CALL = re.compile(r"""(?:import|require)\s*\(\s*['"`]([^'"`]{2,512})['"`]\s*\)""")
WORKER_CTOR = re.compile(
    r"""new\s+(?:Worker|SharedWorker)\s*\(\s*['"`]([^'"`]{2,512})['"`]""", re.IGNORECASE
)
SW_REGISTER = re.compile(
    r"""serviceWorker\s*\.\s*register\s*\(\s*['"`]([^'"`]{2,512})['"`]""", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
CONFIG_KEYS: tuple[str, ...] = (
    "baseURL",
    "baseUrl",
    "base_url",
    "BASE_URL",
    "BASE_PATH",
    "basePath",
    "API_URL",
    "apiUrl",
    "api_url",
    "API_BASE",
    "apiBase",
    "API_BASE_URL",
    "API_ENDPOINT",
    "ENDPOINT",
    "endpoint",
    "endpointUrl",
    "SERVICE_URL",
    "serviceUrl",
    "SERVICE_BASE",
    "HOST",
    "host",
    "hostname",
    "SERVER",
    "server",
    "serverUrl",
    "backendUrl",
    "BACKEND_URL",
    "GRAPHQL",
    "graphqlUrl",
    "GRAPHQL_URL",
    "GRAPHQL_ENDPOINT",
    "TOKEN_URL",
    "tokenUrl",
    "LOGIN_URL",
    "loginUrl",
    "AUTH_URL",
    "authUrl",
    "authority",
    "issuer",
    "REST_URL",
    "restUrl",
    "gatewayUrl",
    "GATEWAY_URL",
    "cdnUrl",
    "CDN_URL",
    "wsUrl",
    "WS_URL",
    "socketUrl",
    "SOCKET_URL",
    "mapService",
    "portalUrl",
    "geoserverUrl",
    "tileUrl",
    "tileURL",
    "wmsUrl",
    "url",
    "uri",
    "href",
    "src",
)
_CONFIG_KEY_ALTERNATION = "|".join(re.escape(key) for key in dict.fromkeys(CONFIG_KEYS))
CONFIG_ASSIGNMENT = re.compile(
    rf"""(?<![\w$])(?P<key>{_CONFIG_KEY_ALTERNATION})\s*[:=]\s*['"`](?P<value>[^'"`\n]{{2,512}})['"`]"""
)
ENV_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Z][A-Z0-9_]{2,60}(?:URL|URI|HOST|ENDPOINT|SERVER|API|PATH))\s*[:=]\s*"""
    r"""['"`](?P<value>[^'"`\n]{2,512})['"`]"""
)

# ---------------------------------------------------------------------------
# Data documents and services
# ---------------------------------------------------------------------------
DATA_FILE = re.compile(
    r"""(?:https?://|/)[^\s'"`<>\\]{1,400}?\.(?:json|geojson|topojson|xml|pbf|mvt|kml|kmz|gpx|csv|yaml|yml|wsdl|rss|atom)"""
    r"""(?:\?[^\s'"`<>\\]*)?""",
    re.IGNORECASE,
)
SOURCEMAP_COMMENT = re.compile(r"""[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)""")
ARCGIS_SERVICE = re.compile(
    r"""(?:https?://|/)[^\s'"`<>\\]{1,400}?/(?:MapServer|FeatureServer|ImageServer|SceneServer|"""
    r"""VectorTileServer|GeometryServer|GPServer|GeocodeServer|GeoDataServer|GlobeServer|StreamServer)"""
    r"""(?:/[^\s'"`<>\\]*)?""",
    re.IGNORECASE,
)
OGC_SERVICE = re.compile(
    r"""(?:https?://|/)[^\s'"`<>\\]{1,400}?/(?:geoserver|mapserv|qgis|ows|wms|wfs|wcs|wmts|cgi-bin/mapserv)"""
    # Without this boundary "mapserv" would match inside ArcGIS "MapServer" URLs.
    r"""(?![A-Za-z0-9])(?:/[^\s'"`<>\\]*)?""",
    re.IGNORECASE,
)
OGC_QUERY = re.compile(r"""[?&](?:SERVICE|service)=(WMS|WMTS|WFS|WCS|CSW)\b""", re.IGNORECASE)
GET_CAPABILITIES = re.compile(r"""REQUEST=GetCapabilities""", re.IGNORECASE)
SWAGGER_DOC = re.compile(
    r"""(?:https?://|/)[^\s'"`<>\\]{0,400}?(?:swagger[-\w]*\.(?:json|yaml|yml)|openapi[-\w]*\.(?:json|yaml|yml)|"""
    r"""/swagger-ui[^\s'"`<>\\]*|/api-docs[^\s'"`<>\\]*|/v\d/api-docs[^\s'"`<>\\]*|/swagger/[^\s'"`<>\\]*)""",
    re.IGNORECASE,
)
GRAPHQL_PATH = re.compile(
    r"""(?:https?://[^\s'"`<>\\]{0,400}?)?/(?:graphql|graphiql|gql|altair|playground)"""
    r"""(?![\w-])(?:/[^\s'"`<>\\]*)?""",
    re.IGNORECASE,
)
GRAPHQL_TAG = re.compile(
    r"""(?:gql|graphql)\s*`\s*(query|mutation|subscription|fragment)\s+([A-Za-z_]\w*)""",
    re.IGNORECASE,
)
GRAPHQL_OPERATION = re.compile(r"""["']?operationName["']?\s*:\s*['"`]([A-Za-z_]\w*)['"`]""")
TILE_TEMPLATE = re.compile(
    r"""(?:https?://|/)[^\s'"`<>\\]{1,400}?\{[zxy-]\}[^\s'"`<>\\]{0,200}""", re.IGNORECASE
)
SOAP_ACTION = re.compile(r"""SOAPAction\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)


@dataclass(slots=True, frozen=True)
class RawMatch:
    """A single raw extraction result.

    Attributes:
        value: The captured URL or path, not yet resolved or normalised.
        method: HTTP verb when the call site revealed one, ``None`` when the rule
            saw no verb at all. The distinction matters: an explicit ``GET`` is
            evidence, a missing verb is merely an absence of it.
        rule: Name of the rule that produced the match, used as evidence label.
        confidence: How reliable this rule is.
        evidence: Short snippet of surrounding source code.
        position: Offset of the match in the source, used for comment filtering.
    """

    value: str
    method: HttpMethod | None = None
    rule: str = "regex"
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""
    position: int = -1


#: Lexer-ish pattern used to locate comments without mistaking a URL's ``//``
#: for one. String literals come first so that ``"https://x"`` is consumed whole,
#: and the line-comment branch additionally refuses a ``//`` preceded by a colon.
_JS_TOKENS = re.compile(
    r"""
    "(?:[^"\\\n]|\\.)*"      # double quoted string
    | '(?:[^'\\\n]|\\.)*'    # single quoted string
    | `(?:[^`\\]|\\.)*`      # template literal
    | /\*[\s\S]*?\*/         # block comment
    | (?<!:)//[^\n]*         # line comment
    """,
    re.VERBOSE,
)


def comment_spans(text: str) -> list[tuple[int, int]]:
    """Locate every comment in a JavaScript or CSS source.

    Args:
        text: Source text to scan.

    Returns:
        Sorted ``(start, end)`` offsets of comment regions.
    """
    spans: list[tuple[int, int]] = []
    for match in _JS_TOKENS.finditer(text):
        token = match.group(0)
        if token.startswith(("/*", "//")):
            spans.append(match.span())
    return spans


def in_comment(spans: list[tuple[int, int]], position: int) -> bool:
    """Whether an offset falls inside one of the given comment spans.

    Args:
        spans: Output of :func:`comment_spans`.
        position: Offset to test; negative values are never inside a comment.

    Returns:
        ``True`` when the offset lies within a comment.
    """
    if position < 0 or not spans:
        return False
    index = bisect_right(spans, (position, len(spans)))
    if index == 0:
        return False
    start, end = spans[index - 1]
    return start <= position < end


def _snippet(text: str, start: int, end: int, radius: int = 60) -> str:
    """Return the source text around a match for evidence purposes."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right]


def _method(raw: str | None) -> HttpMethod | None:
    """Convert a captured verb string into an :class:`HttpMethod`.

    Args:
        raw: The verb as it appeared in the source, or ``None``.

    Returns:
        The parsed verb, or ``None`` when nothing recognisable was captured.
    """
    if not raw:
        return None
    try:
        return HttpMethod(raw.strip().upper())
    except ValueError:
        return None


def iter_call_sites(text: str) -> Iterator[RawMatch]:
    """Yield endpoints extracted from explicit AJAX/HTTP call sites.

    These are the highest confidence matches because the surrounding code proves
    the string is used as a request target.

    Args:
        text: JavaScript (or HTML with inline scripts) source.

    Yields:
        :class:`RawMatch` instances with ``HIGH`` confidence.
    """
    for match in FETCH_WITH_METHOD.finditer(text):
        verb = METHOD_IN_OPTIONS.search(match.group("opts") or "")
        yield RawMatch(
            value=match.group(1),
            method=_method(verb.group(1) if verb else None),
            rule="fetch",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in FETCH_CALL.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="fetch",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in AXIOS_VERB.finditer(text):
        yield RawMatch(
            value=match.group(2),
            method=_method(match.group(1)),
            rule="axios",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for pattern, rule in ((AXIOS_CONFIG, "axios.config"), (AXIOS_CREATE, "axios.create")):
        for match in pattern.finditer(text):
            opts = match.group("opts") or ""
            verb = METHOD_IN_OPTIONS.search(opts)
            for url_match in (URL_IN_OPTIONS.search(opts), BASEURL_IN_OPTIONS.search(opts)):
                if url_match:
                    yield RawMatch(
                        value=url_match.group(1),
                        method=_method(verb.group(1) if verb else None),
                        rule=rule,
                        confidence=Confidence.HIGH,
                        evidence=_snippet(text, *match.span(), radius=20),
                        position=match.start(),
                    )
    for match in XHR_OPEN.finditer(text):
        yield RawMatch(
            value=match.group(2),
            method=_method(match.group(1)),
            rule="XMLHttpRequest",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in JQUERY_AJAX.finditer(text):
        jquery_verb = {
            "get": HttpMethod.GET,
            "getjson": HttpMethod.GET,
            "getscript": HttpMethod.GET,
            "load": HttpMethod.GET,
            "post": HttpMethod.POST,
        }.get(match.group(1).lower(), HttpMethod.GET)
        yield RawMatch(
            value=match.group(2),
            method=jquery_verb,
            rule="jquery.ajax",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in JQUERY_AJAX_CONFIG.finditer(text):
        opts = match.group("opts") or ""
        url_match = URL_IN_OPTIONS.search(opts)
        if url_match:
            verb = METHOD_IN_OPTIONS.search(opts) or re.search(
                r"""type\s*:\s*['"`](\w+)['"`]""", opts
            )
            yield RawMatch(
                value=url_match.group(1),
                method=_method(verb.group(1) if verb else None),
                rule="jquery.ajax",
                confidence=Confidence.HIGH,
                evidence=_snippet(text, *match.span(), radius=20),
                position=match.start(),
            )
    for match in ANGULAR_HTTP.finditer(text):
        yield RawMatch(
            value=match.group(2),
            method=_method(match.group(1)),
            rule="http.client",
            confidence=Confidence.MEDIUM,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in SUPERAGENT.finditer(text):
        superagent_verb = "delete" if match.group(1).lower() == "del" else match.group(1)
        yield RawMatch(
            value=match.group(2),
            method=_method(superagent_verb),
            rule="superagent",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in KY_WRETCH.finditer(text):
        yield RawMatch(
            value=match.group(2),
            method=_method(match.group(1)),
            rule="ky/wretch",
            confidence=Confidence.MEDIUM,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in NAVIGATOR_BEACON.finditer(text):
        yield RawMatch(
            value=match.group(1),
            method=HttpMethod.POST,
            rule="sendBeacon",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in EVENT_SOURCE.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="EventSource",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in SW_REGISTER.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="serviceWorker.register",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in WORKER_CTOR.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="Worker",
            confidence=Confidence.MEDIUM,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )


def iter_websockets(text: str) -> Iterator[RawMatch]:
    """Yield WebSocket URLs from constructors and raw ``ws://`` literals.

    Args:
        text: Source text to scan.

    Yields:
        Matches whose value is a ``ws``/``wss`` URL or a relative socket path.
    """
    for match in WEBSOCKET_CTOR.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="new WebSocket",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )
    for match in WEBSOCKET_URL.finditer(text):
        yield RawMatch(
            value=match.group(0),
            rule="ws-url",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span()),
            position=match.start(),
        )


def iter_config_values(text: str) -> Iterator[RawMatch]:
    """Yield values assigned to endpoint-ish configuration keys.

    Args:
        text: Source text to scan.

    Yields:
        Matches labelled with the configuration key that produced them.
    """
    for pattern in (CONFIG_ASSIGNMENT, ENV_ASSIGNMENT):
        for match in pattern.finditer(text):
            yield RawMatch(
                value=match.group("value"),
                rule=f"config:{match.group('key')}",
                confidence=Confidence.HIGH,
                evidence=_snippet(text, *match.span(), radius=30),
                position=match.start(),
            )


def iter_generic_urls(text: str) -> Iterator[RawMatch]:
    """Yield every URL-shaped literal found in the text.

    This is the broad, low precision sweep; downstream filters remove noise.

    Args:
        text: Source text to scan.

    Yields:
        Matches with ``LOW``/``MEDIUM`` confidence depending on the shape.
    """
    for match in ABSOLUTE_URL.finditer(text):
        yield RawMatch(
            value=match.group(0),
            rule="absolute-url",
            confidence=Confidence.MEDIUM,
            evidence=_snippet(text, *match.span(), radius=30),
            position=match.start(),
        )
    for match in PROTOCOL_RELATIVE_URL.finditer(text):
        yield RawMatch(
            value=match.group(0),
            rule="protocol-relative",
            confidence=Confidence.LOW,
            evidence=_snippet(text, *match.span(), radius=30),
            position=match.start(),
        )
    for match in QUOTED_PATH.finditer(text):
        yield RawMatch(
            value=match.group(1),
            rule="quoted-path",
            confidence=Confidence.LOW,
            evidence=_snippet(text, *match.span(), radius=30),
            position=match.start(),
        )
    for pattern, rule in ((API_PATH, "api-path"), (VERSIONED_PATH, "versioned-path")):
        for match in pattern.finditer(text):
            yield RawMatch(
                value=match.group(0),
                rule=rule,
                confidence=Confidence.MEDIUM,
                evidence=_snippet(text, *match.span(), radius=30),
                position=match.start(),
            )
    for match in DATA_FILE.finditer(text):
        yield RawMatch(
            value=match.group(0),
            rule="data-file",
            confidence=Confidence.MEDIUM,
            evidence=_snippet(text, *match.span(), radius=30),
            position=match.start(),
        )
    for match in TILE_TEMPLATE.finditer(text):
        yield RawMatch(
            value=match.group(0),
            rule="tile-template",
            confidence=Confidence.HIGH,
            evidence=_snippet(text, *match.span(), radius=30),
            position=match.start(),
        )


def iter_service_urls(text: str) -> Iterator[RawMatch]:
    """Yield geospatial and documentation service URLs.

    Args:
        text: Source text to scan.

    Yields:
        Matches for ArcGIS, OGC, Swagger and GraphQL service locations.
    """
    for pattern, rule in (
        (ARCGIS_SERVICE, "arcgis"),
        (OGC_SERVICE, "ogc"),
        (SWAGGER_DOC, "swagger"),
        (GRAPHQL_PATH, "graphql"),
    ):
        for match in pattern.finditer(text):
            yield RawMatch(
                value=match.group(0),
                rule=rule,
                confidence=Confidence.HIGH,
                evidence=_snippet(text, *match.span(), radius=30),
                position=match.start(),
            )


def find_sourcemap(text: str) -> str | None:
    """Return the ``sourceMappingURL`` referenced at the end of an asset.

    Args:
        text: Full JavaScript or CSS source.

    Returns:
        The raw source map reference, or ``None``.
    """
    matches = SOURCEMAP_COMMENT.findall(text)
    return matches[-1].strip() if matches else None


def extract_all(text: str, *, skip_comments: bool = False) -> list[RawMatch]:
    """Run every static rule over a text artefact.

    Args:
        text: JavaScript, CSS, JSON, XML or HTML source.
        skip_comments: Discard matches found inside comments. Enable for
            JavaScript and CSS, where ``@see http://api.jquery.com/data/`` style
            documentation links vastly outnumber real endpoints. Leave disabled
            for XML/JSON/HTML, whose payloads are not comment-delimited code.

    Returns:
        A list of raw matches, ordered from highest to lowest precision so that
        the deduplicating collector keeps the best evidence.
    """
    matches: list[RawMatch] = []
    matches.extend(iter_call_sites(text))
    matches.extend(iter_websockets(text))
    matches.extend(iter_service_urls(text))
    matches.extend(iter_config_values(text))
    matches.extend(iter_generic_urls(text))

    if not skip_comments:
        return matches
    spans = comment_spans(text)
    if not spans:
        return matches
    return [match for match in matches if not in_comment(spans, match.position)]
