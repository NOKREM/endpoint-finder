"""Turn a text artefact (JS/CSS/JSON/XML/HTML) into classified endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from endpoint_finder.discovery import regex as rules
from endpoint_finder.discovery.classifier import classify, guess_method
from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil

#: Third party hosts that add noise without adding attack surface insight.
NOISE_HOSTS: frozenset[str] = frozenset(
    {
        "www.w3.org",
        "schema.org",
        "www.schema.org",
        "purl.org",
        "creativecommons.org",
        "gmpg.org",
        "ogp.me",
        "xmlns.com",
        "docs.oasis-open.org",
        "opengis.net",
        "www.opengis.net",
        "json-schema.org",
        "unpkg.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "www.googletagmanager.com",
        "www.google-analytics.com",
        "connect.facebook.net",
        "github.com",
        "www.npmjs.com",
        "nodejs.org",
        "reactjs.org",
        "vuejs.org",
        "developer.mozilla.org",
        "stackoverflow.com",
        "www.gnu.org",
        "apache.org",
        "www.apache.org",
        "tools.ietf.org",
        "www.ietf.org",
        "registry.npmjs.org",
    }
)

_LICENSE_NOISE = re.compile(
    r"(licen[cs]e|copyright|@author|bugs?|issues?|changelog|readme|documentation)", re.IGNORECASE
)

#: Paths *inside* OOXML/ODF/JAR archives. Spreadsheet and document libraries such
#: as SheetJS, exceljs and docx ship these part names as plain string literals, so
#: they look exactly like site paths ending in ``.xml``. They are never served
#: over HTTP, so a static match on one is always a false positive.
_ARCHIVE_INTERNAL = re.compile(
    r"/(?:_rels|docprops|meta-inf|customxml|persons)/"
    r"|/(?:xl|word|ppt|visio)/(?:media|theme|worksheets|drawings|charts|embeddings)?"
    r"|/\[content_types\]\.xml$"
    r"|/(?:workbook|sharedstrings|calcchain|styles|theme\d*|app|core|custom|document"
    r"|presentation|settings|fonttable|webextension|metadata|person|manifest"
    r"|content|meta)\.xml$",
    re.IGNORECASE,
)

#: How many configuration base URLs a bare path may be speculatively joined to.
MAX_BASE_FANOUT = 2

#: Artefact kinds written in a language with ``//`` and ``/* */`` comments. Only
#: these get comment filtering; XML and JSON payloads are not comment-delimited
#: and a naive scan would mistake ``http://`` for the start of a line comment.
COMMENTED_SOURCES: frozenset[SourceKind] = frozenset(
    {SourceKind.JAVASCRIPT, SourceKind.INLINE_SCRIPT, SourceKind.SOURCEMAP, SourceKind.CSS}
)


@dataclass(slots=True)
class AnalysisContext:
    """Inputs required to resolve and score candidates from one artefact.

    Attributes:
        source_url: URL of the artefact being analysed.
        source_kind: Which kind of artefact it is.
        target: The scan target, used for scope decisions.
        follow_subdomains: Whether sibling subdomains count as in scope.
        keep_external: Keep endpoints hosted on third party domains.
        include: Compiled allow-list patterns.
        exclude: Compiled deny-list patterns.
    """

    source_url: str
    source_kind: SourceKind
    target: str
    follow_subdomains: bool = True
    keep_external: bool = True
    include: list[re.Pattern[str]] | None = None
    exclude: list[re.Pattern[str]] | None = None


def _is_noise(url: str, evidence: str) -> bool:
    """Filter out standards URLs, CDNs, licence boilerplate and archive internals.

    Args:
        url: The resolved candidate URL.
        evidence: Surrounding source snippet.

    Returns:
        ``True`` when the candidate should not be reported.
    """
    host = urlutil.host_of(url)
    if host in NOISE_HOSTS:
        return True
    if _LICENSE_NOISE.search(evidence) and "/api" not in url.lower():
        return True
    if _ARCHIVE_INTERNAL.search(urlsplit(url).path):
        return True
    if urlutil.is_infrastructure_path(url):
        return True
    return bool(urlutil.is_binary_asset(url) and "?" not in url)


def _accept(url: str, ctx: AnalysisContext) -> bool:
    """Apply scope and user filters to a resolved URL."""
    if not urlutil.matches_filters(url, ctx.include or [], ctx.exclude or []):
        return False
    if ctx.keep_external:
        return True
    return urlutil.same_scope(url, ctx.target, follow_subdomains=ctx.follow_subdomains)


def collect_base_urls(text: str) -> list[str]:
    """Extract absolute base URLs assigned to configuration constants.

    These are used to reconstruct endpoints whose path is stored separately from
    the host, a very common bundler pattern.

    Args:
        text: Source text to scan.

    Returns:
        Up to five distinct absolute base URLs.
    """
    bases: list[str] = []
    for match in rules.iter_config_values(text):
        value = urlutil.clean_candidate(match.value)
        if value.startswith(("http://", "https://")) and "${" not in value:
            normalised = urlutil.normalize(value.rstrip("/") or value)
            if normalised and normalised not in bases:
                bases.append(normalised)
        if len(bases) >= 5:
            break
    return bases


def analyze_text(
    text: str,
    ctx: AnalysisContext,
    *,
    extra_bases: list[str] | None = None,
) -> list[Endpoint]:
    """Extract every endpoint candidate from a text artefact.

    Args:
        text: The artefact body.
        ctx: Resolution and filtering context.
        extra_bases: Additional absolute base URLs used to resolve bare paths,
            typically harvested from configuration constants elsewhere in the app.

    Returns:
        A list of endpoints; duplicates are possible and expected to be folded by
        :class:`~endpoint_finder.models.EndpointCollector`.
    """
    if not text:
        return []

    found: list[Endpoint] = []
    bases = [ctx.source_url, *(extra_bases or [])]

    for match in rules.extract_all(text, skip_comments=ctx.source_kind in COMMENTED_SOURCES):
        candidate = urlutil.clean_candidate(match.value)
        if not candidate or not urlutil.is_probably_url(candidate):
            continue
        candidate = urlutil.strip_template_placeholders(candidate)

        resolved_set: list[str] = []
        primary = urlutil.absolutize(ctx.source_url, candidate)
        if primary:
            resolved_set.append(primary)
        # A bare path may belong to a backend host declared in a config constant.
        # Only proven call sites are fanned out, and only over a couple of bases:
        # doing it for every loose path against every known host manufactures
        # endpoints that exist on none of them.
        if candidate.startswith("/") and match.confidence is Confidence.HIGH:
            for base in bases[1 : MAX_BASE_FANOUT + 1]:
                alternative = urlutil.absolutize(base, candidate)
                if alternative and alternative not in resolved_set:
                    resolved_set.append(alternative)

        for position, resolved in enumerate(resolved_set):
            normalised = urlutil.normalize(resolved)
            if (
                not normalised
                or _is_noise(normalised, match.evidence)
                or not _accept(normalised, ctx)
            ):
                continue
            etype = classify(normalised, hint=match.rule)
            # A low precision rule that produced no semantic signal is just noise.
            low_signal = etype is EndpointType.UNKNOWN and match.confidence is Confidence.LOW
            if low_signal and not _has_api_signal(normalised):
                continue
            # Anything beyond the first resolution is a guess about which host
            # serves the path, so it is reported with reduced confidence.
            inferred_base = position > 0
            tags = [f"rule:{match.rule}"]
            if inferred_base:
                tags.append("base:inferred")
            found.append(
                Endpoint(
                    url=normalised,
                    method=guess_method(normalised, etype, match.method),
                    method_observed=match.method is not None and not inferred_base,
                    type=etype,
                    source=ctx.source_kind,
                    source_url=ctx.source_url,
                    evidence=match.evidence or match.value,
                    confidence=Confidence.MEDIUM if inferred_base else match.confidence,
                    tags=tags,
                )
            )
    return found


#: Router paths that address nothing on their own.
_ROUTE_NOISE = frozenset({"", "/", "**", "*", "null", "true", "false", "undefined"})


def extract_spa_routes(text: str, origin: str, limit: int = 120) -> list[str]:
    """Recover the client side routes declared in a bundle's router config.

    A single page application serves the same HTML for every route, so the link
    crawler sees exactly one page no matter how high ``--depth`` is set. The route
    table inside the bundle is the only static record of what else exists, and
    each route must be *rendered* to observe the requests it fires.

    Args:
        text: JavaScript source, typically the main bundle.
        origin: Scheme and host to resolve the routes against.
        limit: Maximum number of routes to return.

    Returns:
        Absolute, normalised page URLs.
    """
    routes: list[str] = []
    for match in rules.SPA_ROUTE.finditer(text):
        route = match.group("route").strip()
        if route.lower() in _ROUTE_NOISE or ":" in route:
            continue
        # Router paths never carry a file extension; anything that does is a
        # bundler asset path that happened to sit next to a "path:" key.
        if "." in route:
            continue
        absolute = urlutil.absolutize(origin, f"/{route.lstrip('/')}")
        normalised = urlutil.normalize(absolute) if absolute else None
        if normalised and normalised not in routes:
            routes.append(normalised)
        if len(routes) >= limit:
            break
    return routes


def resolve_string_variable(text: str, name: str) -> str | None:
    """Find the string literal assigned to a variable in the same file.

    Handles ``var x = "..."``, ``this.x = "..."``, ``$scope.x = "..."`` and object
    literal ``x: "..."`` forms. The last assignment wins, which matches how these
    files are usually written (declaration first, reassignment for environments).

    Args:
        text: Source text of the file.
        name: Variable name, possibly dotted.

    Returns:
        The assigned string, or ``None`` when the variable is not a plain literal.
    """
    if not name:
        return None
    bare = name.rsplit(".", 1)[-1]
    pattern = re.compile(rules.STRING_ASSIGNMENT.format(name=re.escape(bare)))
    matches = pattern.findall(text)
    return matches[-1] if matches else None


def extract_concatenations(text: str, ctx: AnalysisContext) -> list[Endpoint]:
    """Rebuild endpoints written as ``baseVariable + "/path"``.

    This is the highest value recall rule for hand-written front ends: the path
    literal on its own carries no host and no API marker, so every other rule
    either drops it or attaches it to the wrong origin. Requiring the variable to
    resolve to an absolute URL in the same file keeps the precision high.

    Args:
        text: JavaScript source.
        ctx: Resolution and filtering context.

    Returns:
        Endpoints built from resolved concatenations.
    """
    endpoints: list[Endpoint] = []
    resolved: dict[str, str | None] = {}
    spans = rules.comment_spans(text) if ctx.source_kind in COMMENTED_SOURCES else []

    for match in rules.CONCAT_BASE.finditer(text):
        if rules.in_comment(spans, match.start()):
            continue
        name = match.group("name")
        path = match.group("path")
        if name not in resolved:
            value = resolve_string_variable(text, name)
            resolved[name] = value if value and value.startswith(("http://", "https://")) else None
        base = resolved[name]
        if not base:
            continue

        # Emulate the concatenation literally; urljoin would discard the base path.
        combined = f"{base.rstrip('/')}{urlutil.strip_template_placeholders(path)}"
        normalised = urlutil.normalize(combined)
        if not normalised or not _accept(normalised, ctx):
            continue
        etype = classify(normalised, hint="concat")
        endpoints.append(
            Endpoint(
                url=normalised,
                method=guess_method(normalised, etype),
                type=etype,
                source=ctx.source_kind,
                source_url=ctx.source_url,
                evidence=f"{name} + {path!r}",
                confidence=Confidence.HIGH,
                tags=["rule:concat", f"base:{name}"],
            )
        )
    return endpoints


def _has_api_signal(url: str) -> bool:
    """Whether a URL carries at least one endpoint-ish marker."""
    lowered = url.lower()
    return any(marker in lowered for marker in urlutil.API_MARKERS)


def find_sourcemap_url(text: str, source_url: str) -> str | None:
    """Resolve the ``sourceMappingURL`` reference of an asset.

    Args:
        text: Full asset body.
        source_url: URL the asset was downloaded from.

    Returns:
        An absolute source map URL, or ``None`` when there is none or it is inline.
    """
    reference = rules.find_sourcemap(text)
    if not reference or reference.startswith("data:"):
        return None
    resolved = urlutil.absolutize(source_url, reference)
    return urlutil.normalize(resolved) if resolved else None


def extract_graphql_operations(text: str) -> list[tuple[str, str]]:
    """Collect GraphQL operation kinds and names declared in the source.

    Args:
        text: JavaScript source possibly containing ``gql`` tagged templates.

    Returns:
        A list of ``(kind, name)`` tuples, e.g. ``[("query", "GetUser")]``.
    """
    operations: list[tuple[str, str]] = []
    for match in rules.GRAPHQL_TAG.finditer(text):
        operations.append((match.group(1).lower(), match.group(2)))
    for match in rules.GRAPHQL_OPERATION.finditer(text):
        operations.append(("operation", match.group(1)))
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for item in operations:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def extract_websockets(text: str, ctx: AnalysisContext) -> list[Endpoint]:
    """Extract WebSocket endpoints from a source artefact.

    Args:
        text: Source text to scan.
        ctx: Resolution context.

    Returns:
        WebSocket endpoints with the ``ANY`` method.
    """
    endpoints: list[Endpoint] = []
    for match in rules.iter_websockets(text):
        candidate = urlutil.clean_candidate(match.value)
        if not candidate:
            continue
        candidate = urlutil.strip_template_placeholders(candidate)
        if candidate.startswith("/"):
            base = ctx.source_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
            resolved = urlutil.absolutize(base, candidate)
        else:
            resolved = candidate
        normalised = urlutil.normalize(resolved) if resolved else None
        if not normalised or not normalised.startswith(("ws://", "wss://")):
            continue
        if not _accept(normalised, ctx):
            continue
        endpoints.append(
            Endpoint(
                url=normalised,
                method=HttpMethod.ANY,
                type=EndpointType.WEBSOCKET,
                source=ctx.source_kind,
                source_url=ctx.source_url,
                evidence=match.evidence,
                confidence=Confidence.HIGH,
                tags=[f"rule:{match.rule}"],
            )
        )
    return endpoints
