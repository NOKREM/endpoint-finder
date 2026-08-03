"""GraphQL endpoint detection and operation harvesting."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import extract_graphql_operations

GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graphiql",
)

_UI_PATHS = ("/graphiql", "/playground", "/altair", "/voyager")


def is_graphql(url: str) -> bool:
    """Whether a URL points at a GraphQL endpoint or tooling UI.

    Args:
        url: URL to test.

    Returns:
        ``True`` when the path matches a GraphQL convention.
    """
    path = urlsplit(url).path.lower().rstrip("/")
    return path.endswith(("/graphql", "/gql")) or any(marker in path for marker in _UI_PATHS)


def make_endpoint(
    url: str,
    source: SourceKind,
    source_url: str | None = None,
    evidence: str = "",
) -> Endpoint | None:
    """Build a GraphQL endpoint record.

    Args:
        url: Candidate GraphQL URL.
        source: Where the URL was observed.
        source_url: Artefact the URL came from.
        evidence: Supporting snippet.

    Returns:
        The endpoint, or ``None`` when the URL cannot be normalised.
    """
    normalised = urlutil.normalize(url)
    if not normalised:
        return None
    is_ui = any(marker in normalised.lower() for marker in _UI_PATHS)
    return Endpoint(
        url=normalised,
        method=HttpMethod.GET if is_ui else HttpMethod.POST,
        type=EndpointType.GRAPHQL,
        source=source,
        source_url=source_url,
        evidence=evidence or "graphql path",
        confidence=Confidence.HIGH,
        tags=["graphql:ui"] if is_ui else ["graphql:api"],
    )


def operations_from_source(text: str, source_url: str, endpoint_url: str | None) -> list[Endpoint]:
    """Attach discovered GraphQL operation names to the GraphQL endpoint.

    Args:
        text: JavaScript source containing ``gql`` tagged templates.
        source_url: URL of that source file.
        endpoint_url: Known GraphQL endpoint, if any; otherwise operations are
            reported against the source's own origin.

    Returns:
        At most one endpoint carrying every operation name as a tag.
    """
    operations = extract_graphql_operations(text)
    if not operations:
        return []

    target = endpoint_url
    if not target:
        parts = urlsplit(source_url)
        target = urlunsplit((parts.scheme, parts.netloc, "/graphql", "", ""))
    endpoint = make_endpoint(
        target, SourceKind.JAVASCRIPT, source_url, f"{len(operations)} GraphQL operations"
    )
    if endpoint is None:
        return []
    endpoint.tags = sorted({*endpoint.tags, *(f"{kind}:{name}" for kind, name in operations[:60])})
    endpoint.params = sorted({name for _, name in operations})[:60]
    return [endpoint]


def conventional_urls(base_url: str) -> list[str]:
    """Conventional GraphQL locations for a target origin.

    Args:
        base_url: Any URL on the target origin.

    Returns:
        Absolute candidate URLs, normalised and deduplicated.
    """
    parts = urlsplit(base_url)
    candidates: list[str] = []
    for path in GRAPHQL_PATHS:
        candidate = urlutil.normalize(urlunsplit((parts.scheme, parts.netloc, path, "", "")))
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates
