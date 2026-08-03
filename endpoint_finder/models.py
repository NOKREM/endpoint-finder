"""Pydantic domain models shared by every layer of endpoint-finder."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EndpointType(StrEnum):
    """Semantic classification of a discovered endpoint."""

    REST = "REST"
    GRAPHQL = "GraphQL"
    ARCGIS = "ArcGIS REST"
    GEOSERVER = "GeoServer"
    STATIC_JSON = "Static JSON"
    TILE_SERVER = "Tile Server"
    IMAGE_SERVICE = "Image Service"
    AUTH = "Authentication"
    WEBSOCKET = "WebSocket"
    SWAGGER = "Swagger/OpenAPI"
    SOAP = "SOAP"
    STREAM = "Stream/SSE"
    UNKNOWN = "Unknown"


class SourceKind(StrEnum):
    """Where an endpoint was observed."""

    HTML = "HTML"
    INLINE_SCRIPT = "InlineScript"
    JAVASCRIPT = "JavaScript"
    CSS = "CSS"
    SOURCEMAP = "SourceMap"
    NETWORK = "Network"
    WEBSOCKET = "WebSocketFrame"
    ROBOTS = "robots.txt"
    SITEMAP = "sitemap.xml"
    MANIFEST = "manifest.json"
    SERVICE_WORKER = "ServiceWorker"
    COOKIE = "Cookie"
    HEADER = "Header"
    SWAGGER = "OpenAPI"
    GRAPHQL_SCHEMA = "GraphQLSchema"
    ARCGIS_CATALOG = "ArcGISCatalog"
    CAPABILITIES = "GetCapabilities"
    WELL_KNOWN = "well-known"
    JSON = "JSON"
    XML = "XML"


class HttpMethod(StrEnum):
    """HTTP verbs recognised by the tool."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    ANY = "ANY"


class Confidence(StrEnum):
    """How certain the extractor is that the candidate is a real endpoint."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Endpoint(BaseModel):
    """A single discovered endpoint.

    Attributes:
        url: Absolute, normalised URL of the endpoint.
        method: HTTP verb (observed or inferred).
        method_observed: ``True`` when the verb was proven by a call site, a live
            request or an API description, ``False`` when it was only inferred.
        type: Semantic classification, see :class:`EndpointType`.
        source: The kind of artefact the endpoint was extracted from.
        source_url: URL of the concrete artefact (JS file, page, sourcemap ...).
        evidence: Short raw snippet proving the match, useful for manual triage.
        confidence: Extractor certainty.
        status_code: HTTP status, only present for endpoints observed in the browser.
        content_type: Response content type when observed.
        params: Query/body parameter names known for this endpoint.
        tags: Free-form labels (e.g. ``swagger:operationId``).
        discovered_at: UTC timestamp of the discovery.
    """

    model_config = ConfigDict(use_enum_values=False, populate_by_name=True)

    url: str
    method: HttpMethod = HttpMethod.GET
    method_observed: bool = False
    type: EndpointType = EndpointType.UNKNOWN
    source: SourceKind = SourceKind.JAVASCRIPT
    source_url: str | None = None
    evidence: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    status_code: int | None = None
    content_type: str | None = None
    params: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("evidence")
    @classmethod
    def _trim_evidence(cls, value: str | None) -> str | None:
        """Keep evidence snippets short enough for terminal and report output."""
        if value is None:
            return None
        collapsed = " ".join(value.split())
        return collapsed[:240]

    @property
    def key(self) -> tuple[str, str]:
        """Deduplication key: verb + url."""
        return (self.method.value, self.url)

    def merge(self, other: Endpoint) -> None:
        """Fold another observation of the same endpoint into this one.

        Higher confidence, richer typing and network evidence always win.

        Args:
            other: A duplicate endpoint carrying possibly better information.
        """
        self.method_observed = self.method_observed or other.method_observed
        rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
        if rank[other.confidence] > rank[self.confidence]:
            self.confidence = other.confidence
            self.evidence = other.evidence or self.evidence
        if self.type is EndpointType.UNKNOWN and other.type is not EndpointType.UNKNOWN:
            self.type = other.type
        if self.status_code is None and other.status_code is not None:
            self.status_code = other.status_code
            self.source = other.source
            self.source_url = other.source_url or self.source_url
        if self.content_type is None:
            self.content_type = other.content_type
        self.params = sorted(set(self.params) | set(other.params))
        self.tags = sorted(set(self.tags) | set(other.tags))


class Asset(BaseModel):
    """A downloadable artefact referenced by the target."""

    url: str
    kind: str = "other"
    referrer: str | None = None
    content_type: str | None = None
    size: int | None = None


class ScanError(BaseModel):
    """A recoverable failure recorded during the scan."""

    url: str
    category: str
    message: str
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanStats(BaseModel):
    """Aggregate counters for the run."""

    pages: int = 0
    scripts: int = 0
    stylesheets: int = 0
    sourcemaps: int = 0
    requests: int = 0
    assets_downloaded: int = 0
    bytes_downloaded: int = 0
    verified: int = 0
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    """Complete result of a scan, the object every reporter consumes."""

    model_config = ConfigDict(use_enum_values=False)

    target: str
    scan_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    page_title: str | None = None
    stats: ScanStats = Field(default_factory=ScanStats)
    endpoints: list[Endpoint] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    #: Client side routes of a single page application. These are navigable
    #: views, not request targets, so they are reported apart from endpoints.
    routes: list[str] = Field(default_factory=list)
    #: Protection layer sitting in front of the target, when one was detected.
    protection: str | None = None
    #: How many responses were challenges or rate limits rather than content.
    challenges: int = 0

    @property
    def scripts(self) -> int:
        """Number of JavaScript files analysed (kept for report compatibility)."""
        return self.stats.scripts

    @property
    def requests(self) -> int:
        """Number of network requests captured by the browser."""
        return self.stats.requests

    def by_type(self) -> dict[EndpointType, list[Endpoint]]:
        """Group endpoints by their semantic type, preserving insertion order."""
        grouped: dict[EndpointType, list[Endpoint]] = {}
        for endpoint in self.endpoints:
            grouped.setdefault(endpoint.type, []).append(endpoint)
        return grouped

    def type_counts(self) -> dict[str, int]:
        """Return a ``{type: count}`` mapping sorted by descending count."""
        counts = {etype.value: len(items) for etype, items in self.by_type().items()}
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


class EndpointCollector:
    """Deduplicating sink for endpoints.

    The collector is intentionally not a pydantic model: it is mutable working
    state shared between concurrent producers.
    """

    def __init__(self) -> None:
        """Create an empty collector."""
        self._items: dict[tuple[str, str], Endpoint] = {}

    def add(self, endpoint: Endpoint | None) -> None:
        """Add an endpoint, merging it with an existing duplicate when needed.

        Args:
            endpoint: Endpoint to record. ``None`` is ignored for caller convenience.
        """
        if endpoint is None:
            return
        existing = self._items.get(endpoint.key)
        if existing is None:
            self._items[endpoint.key] = endpoint
        else:
            existing.merge(endpoint)

    def extend(self, endpoints: Iterable[Endpoint]) -> None:
        """Add every endpoint of an iterable.

        Args:
            endpoints: Iterable of endpoints to record.
        """
        for endpoint in endpoints:
            self.add(endpoint)

    def __len__(self) -> int:
        """Number of unique endpoints collected so far."""
        return len(self._items)

    def __contains__(self, item: object) -> bool:
        """Membership test on the ``(method, url)`` key."""
        return item in self._items

    def urls(self) -> set[str]:
        """Set of every unique URL collected so far."""
        return {endpoint.url for endpoint in self._items.values()}

    def sorted(self) -> list[Endpoint]:
        """Return endpoints ordered by type then URL, ready for reporting."""
        return sorted(self._items.values(), key=lambda e: (e.type.value, e.url, e.method.value))
