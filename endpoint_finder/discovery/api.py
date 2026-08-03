"""REST aggregation helpers: enrichment, grouping and noise reduction."""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit

from endpoint_finder.discovery.classifier import interest_score
from endpoint_finder.models import Confidence, Endpoint, EndpointType
from endpoint_finder.parser import urls as urlutil

_NUMERIC_SEGMENT = re.compile(r"^\d{1,12}$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HASH_SEGMENT = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def enrich(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Populate query parameter names on every endpoint.

    Args:
        endpoints: Endpoints to enrich in place.

    Returns:
        The same list, for chaining.
    """
    for endpoint in endpoints:
        query = urlsplit(endpoint.url).query
        if not query:
            continue
        names = {name for name, _ in parse_qsl(query, keep_blank_values=True) if name}
        if names:
            endpoint.params = sorted(set(endpoint.params) | names)
    return endpoints


def templatize(url: str) -> str:
    """Replace identifier-looking path segments with ``{id}``.

    ``/api/users/4213/orders/9f2c`` becomes ``/api/users/{id}/orders/{id}``, which
    lets the report collapse hundreds of concrete URLs into a handful of routes.

    Args:
        url: Absolute URL.

    Returns:
        The templated URL.
    """
    parts = urlsplit(url)
    segments = parts.path.split("/")
    rebuilt = [
        (
            "{id}"
            if segment
            and (
                _NUMERIC_SEGMENT.match(segment)
                or _UUID_SEGMENT.match(segment)
                or _HASH_SEGMENT.match(segment)
            )
            else segment
        )
        for segment in segments
    ]
    path = "/".join(rebuilt)
    base = f"{parts.scheme}://{parts.netloc}{path}"
    return f"{base}?{parts.query}" if parts.query else base


def group_routes(endpoints: list[Endpoint]) -> dict[str, list[Endpoint]]:
    """Group endpoints by their templated route.

    Args:
        endpoints: Endpoints to group.

    Returns:
        A mapping of templated route to the endpoints that share it.
    """
    grouped: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        grouped[templatize(endpoint.url)].append(endpoint)
    return dict(grouped)


def group_by_host(endpoints: list[Endpoint]) -> dict[str, list[Endpoint]]:
    """Group endpoints by hostname.

    Args:
        endpoints: Endpoints to group.

    Returns:
        A mapping of host to endpoints, sorted by descending endpoint count.
    """
    grouped: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        grouped[urlsplit(endpoint.url).hostname or "?"].append(endpoint)
    return dict(sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])))


def filter_by_confidence(endpoints: list[Endpoint], minimum: str) -> list[Endpoint]:
    """Drop endpoints below a confidence threshold.

    Args:
        endpoints: Endpoints to filter.
        minimum: One of ``low``, ``medium``, ``high``.

    Returns:
        The endpoints meeting the threshold.
    """
    try:
        floor = _CONFIDENCE_RANK[Confidence(minimum.lower())]
    except (ValueError, KeyError):
        floor = 0
    return [e for e in endpoints if _CONFIDENCE_RANK[e.confidence] >= floor]


def apply_filters(
    endpoints: list[Endpoint],
    include: list[re.Pattern[str]],
    exclude: list[re.Pattern[str]],
) -> list[Endpoint]:
    """Apply the user's include/exclude regexes to the final endpoint list.

    Individual producers filter as early as they can, but schema expansion and
    metadata parsing create endpoints that never passed through those checks.
    Enforcing the rules once more here guarantees the report honours them.

    Args:
        endpoints: Endpoints to filter.
        include: When non-empty, at least one pattern must match.
        exclude: Any match rejects the endpoint.

    Returns:
        The surviving endpoints.
    """
    if not include and not exclude:
        return endpoints
    return [
        endpoint
        for endpoint in endpoints
        if not any(pattern.search(endpoint.url) for pattern in exclude)
        and (not include or any(pattern.search(endpoint.url) for pattern in include))
    ]


def filter_by_host(
    endpoints: list[Endpoint], allow: list[str], deny: list[str] | None = None
) -> list[Endpoint]:
    """Keep only endpoints whose host passes the allow and deny host filters.

    Args:
        endpoints: Endpoints to filter.
        allow: ``--host`` suffixes; empty means no restriction.
        deny: ``--exclude-host`` suffixes; a match always rejects.

    Returns:
        The surviving endpoints.
    """
    deny = deny or []
    if not allow and not deny:
        return endpoints
    return [endpoint for endpoint in endpoints if urlutil.host_allowed(endpoint.url, allow, deny)]


def split_routes(endpoints: list[Endpoint], routes: list[str]) -> tuple[list[Endpoint], list[str]]:
    """Separate navigable SPA routes from actual request targets.

    Route discovery feeds the renderer, but a route such as ``/map`` is a view the
    user navigates to, not an API call. Leaving them among the endpoints inflates
    the count with things nothing ever requests. A route that *also* classified as
    a real endpoint type is kept in both lists, since the evidence says it is used
    as a request target as well.

    Args:
        endpoints: Final endpoint list.
        routes: Discovered client side routes.

    Returns:
        A tuple of ``(endpoints_without_plain_routes, sorted_routes)``.
    """
    if not routes:
        return endpoints, []
    variants = {route.rstrip("/") for route in routes}
    kept = [
        endpoint
        for endpoint in endpoints
        if not (endpoint.url.rstrip("/") in variants and endpoint.type is EndpointType.UNKNOWN)
    ]
    return kept, sorted(variants)


def prefer_observed_methods(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Drop inferred verbs for URLs whose verb is already known.

    A URL such as ``/api/items/save`` is matched both by the ``axios.put`` call
    site (verb proven) and by the generic path sweep (verb guessed as POST).
    Reporting both would invent an endpoint that does not exist, so once any
    observation proves a verb for a URL, the guesses for that URL are removed.

    Args:
        endpoints: Endpoints to filter.

    Returns:
        The endpoints with redundant guesses removed.
    """
    proven: set[str] = {e.url for e in endpoints if e.method_observed}
    if not proven:
        return endpoints
    return [e for e in endpoints if e.method_observed or e.url not in proven]


def drop_unknown(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Remove unclassified endpoints.

    Args:
        endpoints: Endpoints to filter.

    Returns:
        Only endpoints with a recognised type.
    """
    return [e for e in endpoints if e.type is not EndpointType.UNKNOWN]


def rank(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Order endpoints so the most interesting appear first.

    Args:
        endpoints: Endpoints to sort.

    Returns:
        A new list sorted by interest score, confidence and URL.
    """
    return sorted(
        endpoints,
        key=lambda e: (
            -interest_score(e.type),
            -_CONFIDENCE_RANK[e.confidence],
            e.url,
            e.method.value,
        ),
    )


def summarize(endpoints: list[Endpoint]) -> dict[str, int]:
    """Build the counters shown in the report header.

    Args:
        endpoints: Final endpoint list.

    Returns:
        A dictionary of summary counters.
    """
    hosts = {urlsplit(e.url).hostname for e in endpoints if urlsplit(e.url).hostname}
    return {
        "total": len(endpoints),
        "hosts": len(hosts),
        "routes": len(group_routes(endpoints)),
        "high_confidence": sum(1 for e in endpoints if e.confidence is Confidence.HIGH),
        "observed": sum(1 for e in endpoints if e.status_code is not None),
    }
