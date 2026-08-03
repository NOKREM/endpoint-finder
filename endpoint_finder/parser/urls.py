"""URL normalisation, scoping and candidate sanity checks.

Every URL that enters the pipeline passes through :func:`normalize` so that the
deduplication key is stable regardless of where the URL was found.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from endpoint_finder.config import ANALYSABLE_EXTENSIONS, BINARY_EXTENSIONS

#: Suffixes that behave as a single TLD component (approximate public suffix list).
_MULTI_PART_TLDS: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "net.uk",
        "com.tr",
        "org.tr",
        "net.tr",
        "gov.tr",
        "edu.tr",
        "bel.tr",
        "k12.tr",
        "av.tr",
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "edu.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.ar",
        "com.sg",
        "com.hk",
        "com.tw",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "co.kr",
        "or.kr",
        "go.kr",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "ac.in",
        "co.za",
        "org.za",
        "gov.za",
        "co.nz",
        "net.nz",
        "govt.nz",
        "com.es",
        "gob.es",
        "com.pl",
        "gov.pl",
        "com.ua",
        "gov.ua",
        "com.sa",
        "gov.sa",
        "com.eg",
        "gov.eg",
        "com.my",
        "gov.my",
    }
)

#: Characters that terminate a URL literal inside source code. Braces are *not*
#: terminators: tile schemes (``/{z}/{x}/{y}.pbf``) and templated routes
#: (``/api/${id}``) must survive intact so they can be reported as one endpoint.
_URL_TERMINATORS = "\"'`<>|^\\ \t\r\n"

_TEMPLATE_PLACEHOLDER = re.compile(r"\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>|%[0-9a-fA-F]{2}")

#: Signatures of JavaScript source that leaked into a "URL" candidate. Minified
#: bundles are full of regex literals such as ``/\s+/g;n.parseJSON=function(b){``
#: whose leading slash makes them look like a path.
_CODE_FRAGMENT = re.compile(
    r"""=\s*function|function\s*\(|\)\s*\{|\}\s*[;)(]|=>|;\s*[A-Za-z_$][\w$]*\s*[.(]"""
    r"""|\breturn\b|\btypeof\b|\binstanceof\b|\bprototype\b"""
)

#: A syntactically valid host: dotted labels ending in an alphabetic TLD, an IPv4
#: literal, or a bare name such as ``localhost``.
_VALID_HOST = re.compile(
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    r"|\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-f:]+\]"
    r"|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$",
    re.IGNORECASE,
)
_DATA_LIKE = re.compile(r"^(data|blob|javascript|mailto|tel|sms|about|chrome|moz-extension):", re.I)
_MIME_LIKE = re.compile(r"^[a-z]+/[a-z0-9.+-]+$", re.I)
_VERSION_LIKE = re.compile(r"^/?\d+(\.\d+)+/?$")
_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")

#: Endpoint-ish path markers that keep a low-signal candidate alive.
API_MARKERS: tuple[str, ...] = (
    "/api",
    "/rest",
    "/graphql",
    "/gql",
    "/v1/",
    "/v2/",
    "/v3/",
    "/v4/",
    "/services/",
    "/service/",
    "/rpc",
    "/ajax",
    "/json",
    "/data/",
    "/query",
    "mapserver",
    "featureserver",
    "imageserver",
    "sceneserver",
    "vectortileserver",
    "geometryserver",
    "gpserver",
    "geoserver",
    "geocode",
    "/ows",
    "/wms",
    "/wfs",
    "/wmts",
    "/wcs",
    "getcapabilities",
    "/oauth",
    "/token",
    "/login",
    "/auth",
    "/swagger",
    "/openapi",
    "/api-docs",
    "/.well-known/",
    "/sitemap",
    "/feed",
    "/rss",
    "/upload",
    "/download",
    "/export",
    "/search",
    "/session",
)


def clean_candidate(raw: str) -> str:
    """Normalise a raw string extracted from source code into a URL candidate.

    Handles escaped slashes, unicode escapes, HTML entities and stray delimiters.

    Args:
        raw: Raw substring captured by an extractor.

    Returns:
        A cleaned candidate, possibly empty when nothing usable remains.
    """
    if not raw:
        return ""
    value = raw.strip().strip("\"'`")
    value = value.replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/")
    value = value.replace("\\u0026", "&").replace("&amp;", "&")
    value = value.replace("\\n", "").replace("\\r", "").replace("\\t", "")
    value = value.replace("\\\\", "\\")
    # Cut at the first character that cannot appear in a URL literal.
    for index, char in enumerate(value):
        if char in _URL_TERMINATORS:
            value = value[:index]
            break
    return _trim_trailing_punctuation(value.strip())


def _trim_trailing_punctuation(value: str) -> str:
    """Strip sentence and markup punctuation that trails a URL in prose.

    ``http://api.jquery.com/data/)`` and ``http://x/a.html)**`` come from comments
    and documentation, where the URL is followed by prose. Closing brackets are
    only removed when they are unbalanced, so genuinely bracketed URLs such as
    Wikipedia's ``/wiki/Foo_(bar)`` survive.

    Args:
        value: A candidate whose trailing characters may not belong to it.

    Returns:
        The trimmed candidate.
    """
    while value:
        last = value[-1]
        if last in ",;:!*'\"":
            value = value[:-1]
            continue
        if last == "." and not value.endswith(".."):
            value = value[:-1]
            continue
        if last in ")]}" and value.count(last) > value.count(_OPENING[last]):
            value = value[:-1]
            continue
        break
    return value


_OPENING = {")": "(", "]": "[", "}": "{"}


def is_probably_url(candidate: str) -> bool:
    """Heuristic filter separating real URL candidates from source-code noise.

    Args:
        candidate: A cleaned candidate string.

    Returns:
        ``True`` when the candidate is worth resolving into an endpoint.
    """
    value = candidate.strip()
    if len(value) < 2 or len(value) > 2048:
        return False
    if _DATA_LIKE.match(value):
        return False
    if _CODE_FRAGMENT.search(value):
        return False
    if value.startswith("#") or value in {"/", "//", "./", "../"}:
        return False
    if _MIME_LIKE.match(value) and "/" in value and not value.startswith("/"):
        return False
    if _VERSION_LIKE.match(value):
        return False
    if value.startswith(("http://", "https://", "ws://", "wss://", "//")):
        return True
    if not value.startswith("/"):
        return False
    # Reject CSS/SVG fragments and pure punctuation paths.
    if re.fullmatch(r"/[*+\-.,;:!?()\[\]{}=<>~^|&%$#@ ]*", value):
        return False
    # A single short segment with no dot and no API marker is usually noise.
    lowered = value.lower()
    if any(marker in lowered for marker in API_MARKERS):
        return True
    segments = [segment for segment in value.split("/") if segment]
    if not segments:
        return False
    return bool(len(segments) >= 2 or "." in segments[0] or len(segments[0]) >= 3)


def absolutize(base: str, candidate: str) -> str | None:
    """Resolve a candidate against a base URL.

    Args:
        base: Absolute URL of the artefact the candidate was found in.
        candidate: Relative or absolute candidate.

    Returns:
        An absolute URL, or ``None`` when resolution is impossible.
    """
    value = candidate.strip()
    if not value:
        return None
    if value.startswith("//"):
        scheme = urlsplit(base).scheme or "https"
        value = f"{scheme}:{value}"
    if _HAS_SCHEME.match(value):
        if not value.lower().startswith(("http://", "https://", "ws://", "wss://")):
            return None
        return value
    try:
        return urljoin(base, value)
    except ValueError:
        return None


def normalize(url: str, *, keep_query: bool = True) -> str | None:
    """Canonicalise an absolute URL for stable deduplication.

    Lowercases the scheme and host, removes default ports, collapses ``.``/``..``
    segments, drops the fragment and strips a trailing ``?``.

    Args:
        url: Absolute URL to normalise.
        keep_query: Preserve the query string; disable to group parameterised URLs.

    Returns:
        The normalised URL, or ``None`` when the input is not a usable URL.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https", "ws", "wss"}:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or not _VALID_HOST.match(host):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    default_ports = {"http": 80, "https": 443, "ws": 80, "wss": 443}
    netloc = host if port in (None, default_ports.get(scheme)) else f"{host}:{port}"
    if parts.username:
        credentials = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{credentials}@{netloc}"

    path = parts.path or "/"
    if "//" in path:
        path = re.sub(r"/{2,}", "/", path)
    if "." in path:
        normalised = posixpath.normpath(path)
        if path.endswith("/") and not normalised.endswith("/"):
            normalised += "/"
        path = normalised if normalised != "." else "/"
    query = parts.query if keep_query else ""
    return urlunsplit((scheme, netloc, path, query, ""))


def registered_domain(host: str) -> str:
    """Return the approximate registrable domain (eTLD+1) of a host.

    Args:
        host: Hostname, with or without a port.

    Returns:
        The registrable domain, or the input when it cannot be reduced.
    """
    host = host.split(":")[0].lower().strip(".")
    if not host or re.fullmatch(r"[\d.]+", host) or ":" in host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_PART_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def host_of(url: str) -> str:
    """Extract the lowercase hostname of a URL.

    Args:
        url: Absolute URL.

    Returns:
        The hostname, empty when the URL has none.
    """
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def same_scope(
    url: str,
    base: str,
    *,
    follow_subdomains: bool = True,
    same_origin_only: bool = False,
) -> bool:
    """Decide whether a URL belongs to the scanned scope.

    Args:
        url: Candidate URL.
        base: The scan target URL.
        follow_subdomains: Treat ``sub.example.com`` as in-scope for ``example.com``.
        same_origin_only: Require an exact scheme+host+port match.

    Returns:
        ``True`` when the URL may be crawled.
    """
    url_parts = urlsplit(url)
    base_parts = urlsplit(base)
    if same_origin_only:
        return (url_parts.scheme, url_parts.netloc) == (base_parts.scheme, base_parts.netloc)
    url_host = (url_parts.hostname or "").lower()
    base_host = (base_parts.hostname or "").lower()
    if not url_host or not base_host:
        return False
    if url_host == base_host:
        return True
    if not follow_subdomains:
        return False
    return registered_domain(url_host) == registered_domain(base_host)


def extension(url: str) -> str:
    """Return the lowercase file extension of a URL path.

    Args:
        url: Absolute or relative URL.

    Returns:
        The extension including the dot, or an empty string.
    """
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    name = posixpath.basename(unquote(path))
    if "." not in name:
        return ""
    ext = name[name.rfind(".") :].lower()
    return ext if re.fullmatch(r"\.[a-z0-9]{1,10}", ext) else ""


#: Reserved path prefixes belonging to a CDN or protection layer rather than to
#: the application. ``/cdn-cgi/`` in particular is Cloudflare's own namespace on
#: every zone: its challenge, beacon and email-protection calls show up as live
#: XHR traffic and would otherwise be reported as the target's own API.
INFRASTRUCTURE_PATHS: tuple[str, ...] = (
    "/cdn-cgi/",
    "/_incapsula_resource",
    "/_sucuri/",
    "/akam/",
    "/_vercel/insights",
    "/_vercel/speed-insights",
    "/__nextjs_original-stack-frame",
    "/.well-known/traffic-advice",
)


def is_infrastructure_path(url: str) -> bool:
    """Whether a URL belongs to CDN or WAF plumbing rather than the application.

    Args:
        url: Absolute URL to test.

    Returns:
        ``True`` when the path is owned by the infrastructure in front of the site.
    """
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return any(marker in path for marker in INFRASTRUCTURE_PATHS)


def is_binary_asset(url: str) -> bool:
    """Whether the URL points at a binary asset that cannot contain endpoints.

    Args:
        url: URL to inspect.

    Returns:
        ``True`` for images, fonts, media and archives.
    """
    return extension(url) in BINARY_EXTENSIONS


def is_analysable(url: str) -> bool:
    """Whether the URL points at a text artefact worth downloading and parsing.

    Args:
        url: URL to inspect.

    Returns:
        ``True`` for scripts, styles, maps and structured data documents.
    """
    return extension(url) in ANALYSABLE_EXTENSIONS


def is_html_like(url: str) -> bool:
    """Whether the URL is likely to serve an HTML document.

    Args:
        url: URL to inspect.

    Returns:
        ``True`` for extension-less paths and classic HTML extensions.
    """
    ext = extension(url)
    return ext in {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".do", ".action"}


def strip_template_placeholders(url: str) -> str:
    """Replace template placeholders with a neutral token.

    ``https://x/api/${id}/detail`` becomes ``https://x/api/:var/detail`` so that
    templated URLs collapse into a single reported endpoint.

    Args:
        url: URL possibly containing ``${...}`` or ``{{...}}`` placeholders.

    Returns:
        The URL with placeholders replaced.
    """
    return _TEMPLATE_PLACEHOLDER.sub(":var", url)


def normalise_host_suffix(value: str) -> str:
    """Normalise a user supplied host filter into a bare domain suffix.

    Accepts ``example.com``, ``.example.com``, ``*.example.com`` and a full URL,
    all of which reduce to ``example.com``.

    Args:
        value: Raw ``--host`` argument.

    Returns:
        The lowercase domain suffix, empty when nothing usable was given.
    """
    candidate = value.strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.removeprefix("*.").strip(".")
    return candidate.split("/")[0].split(":")[0]


def host_matches(url: str, suffixes: list[str]) -> bool:
    """Whether a URL's host equals or is a subdomain of an allowed suffix.

    Unlike :func:`matches_filters`, only the hostname is considered. A tracking
    URL that carries the target address in a query parameter therefore does not
    slip through.

    Args:
        url: Absolute URL to test.
        suffixes: Normalised domain suffixes; an empty list allows everything.

    Returns:
        ``True`` when the URL is in scope.
    """
    if not suffixes:
        return True
    host = host_of(url)
    if not host:
        return False
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def host_allowed(url: str, allow: list[str], deny: list[str]) -> bool:
    """Apply both host filters, with the deny list taking precedence.

    Args:
        url: Absolute URL to test.
        allow: ``--host`` suffixes; empty allows every host.
        deny: ``--exclude-host`` suffixes; a match always rejects.

    Returns:
        ``True`` when the URL's host survives both filters.
    """
    if deny and host_matches(url, deny):
        return False
    return host_matches(url, allow)


def matches_filters(
    url: str, include: list[re.Pattern[str]], exclude: list[re.Pattern[str]]
) -> bool:
    """Apply user supplied include/exclude regular expressions.

    Args:
        url: URL under test.
        include: When non-empty, at least one pattern must match.
        exclude: Any match rejects the URL.

    Returns:
        ``True`` when the URL survives filtering.
    """
    if any(pattern.search(url) for pattern in exclude):
        return False
    if include:
        return any(pattern.search(url) for pattern in include)
    return True


def parent_service_url(url: str, marker: str) -> str | None:
    """Truncate a URL right after a service marker segment.

    Used to turn ``.../rest/services/Foo/MapServer/3/query`` into
    ``.../rest/services/Foo/MapServer``.

    Args:
        url: Full URL.
        marker: Case-insensitive segment marker such as ``MapServer``.

    Returns:
        The truncated URL, or ``None`` when the marker is absent.
    """
    parts = urlsplit(url)
    segments = parts.path.split("/")
    lowered = [segment.lower() for segment in segments]
    marker = marker.lower()
    for index, segment in enumerate(lowered):
        if segment == marker:
            path = "/".join(segments[: index + 1])
            return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return None
