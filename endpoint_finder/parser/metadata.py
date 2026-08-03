"""Parsers for site metadata: robots.txt, sitemaps, manifests, headers and cookies."""

from __future__ import annotations

import re
from typing import Any

import orjson
from lxml import etree

from endpoint_finder.discovery.classifier import classify, guess_method
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

_SITEMAP_LINE = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_RULE_LINE = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CSP_SOURCE = re.compile(
    r"(?:connect-src|default-src|script-src|frame-src)\s+([^;]+)", re.IGNORECASE
)
_LINK_HEADER = re.compile(r"<([^>]+)>")
_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>\\]+", re.IGNORECASE)


def _make(
    url: str,
    source: SourceKind,
    source_url: str,
    evidence: str,
    *,
    confidence: Confidence = Confidence.MEDIUM,
    method: HttpMethod | None = None,
) -> Endpoint | None:
    """Build a normalised endpoint, returning ``None`` when the URL is unusable."""
    normalised = urlutil.normalize(urlutil.strip_template_placeholders(url))
    if not normalised:
        return None
    etype = classify(normalised, hint=source.value)
    return Endpoint(
        url=normalised,
        method=guess_method(normalised, etype, method),
        method_observed=method is not None,
        type=etype,
        source=source,
        source_url=source_url,
        evidence=evidence,
        confidence=confidence,
    )


def parse_robots(text: str, base_url: str) -> tuple[list[Endpoint], list[str]]:
    """Extract disallowed paths and sitemap references from ``robots.txt``.

    Disallow rules frequently reveal private API prefixes that appear nowhere else.

    Args:
        text: Body of ``robots.txt``.
        base_url: URL the file was fetched from.

    Returns:
        A tuple of endpoints and sitemap URLs to follow.
    """
    endpoints: list[Endpoint] = []
    sitemaps: list[str] = []

    for match in _SITEMAP_LINE.finditer(text):
        resolved = urlutil.absolutize(base_url, match.group(1).strip())
        normalised = urlutil.normalize(resolved) if resolved else None
        if normalised and normalised not in sitemaps:
            sitemaps.append(normalised)

    for match in _RULE_LINE.finditer(text):
        path = match.group(1).strip()
        if path in {"/", "*", ""}:
            continue
        candidate = path.replace("*", "").rstrip("$")
        if not urlutil.is_probably_url(candidate):
            continue
        resolved = urlutil.absolutize(base_url, candidate)
        if not resolved:
            continue
        endpoint = _make(
            resolved,
            SourceKind.ROBOTS,
            base_url,
            match.group(0).strip(),
            confidence=Confidence.MEDIUM,
        )
        if endpoint:
            endpoints.append(endpoint)
    return endpoints, sitemaps


def parse_sitemap(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Parse a sitemap or sitemap index.

    Args:
        text: XML body of the sitemap.
        base_url: URL the sitemap was fetched from.

    Returns:
        A tuple of ``(page_urls, nested_sitemap_urls)``.
    """
    pages: list[str] = []
    nested: list[str] = []
    try:
        parser = etree.XMLParser(recover=True, resolve_entities=False, no_network=True)
        root = etree.fromstring(text.encode("utf-8", "ignore"), parser=parser)
    except (etree.XMLSyntaxError, ValueError) as exc:
        logger.debug("sitemap parse failed for %s: %s", base_url, exc)
        return [], []
    if root is None:
        return [], []

    is_index = etree.QName(root).localname.lower() == "sitemapindex" if root.tag else False
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        if etree.QName(element).localname.lower() != "loc" or not element.text:
            continue
        resolved = urlutil.absolutize(base_url, element.text.strip())
        normalised = urlutil.normalize(resolved) if resolved else None
        if not normalised:
            continue
        parent_name = (
            etree.QName(element.getparent()).localname.lower()
            if element.getparent() is not None and isinstance(element.getparent().tag, str)
            else ""
        )
        if is_index or parent_name == "sitemap":
            nested.append(normalised)
        else:
            pages.append(normalised)
    return pages, nested


def parse_manifest(text: str, base_url: str) -> list[Endpoint]:
    """Extract URLs from a web app manifest.

    Args:
        text: JSON body of ``manifest.json`` / ``site.webmanifest``.
        base_url: URL the manifest was fetched from.

    Returns:
        Endpoints for start URLs, scopes, share targets and related applications.
    """
    try:
        data: Any = orjson.loads(text)
    except orjson.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    endpoints: list[Endpoint] = []
    candidates: list[tuple[str, str]] = []
    for key in ("start_url", "scope", "id"):
        value = data.get(key)
        if isinstance(value, str) and value:
            candidates.append((key, value))
    share_target = data.get("share_target")
    if isinstance(share_target, dict):
        action = share_target.get("action")
        if isinstance(action, str):
            candidates.append(("share_target.action", action))
    for related in data.get("related_applications") or []:
        if isinstance(related, dict) and isinstance(related.get("url"), str):
            candidates.append(("related_applications", related["url"]))
    for shortcut in data.get("shortcuts") or []:
        if isinstance(shortcut, dict) and isinstance(shortcut.get("url"), str):
            candidates.append(("shortcuts", shortcut["url"]))

    for key, value in candidates:
        resolved = urlutil.absolutize(base_url, value)
        if not resolved:
            continue
        method = HttpMethod.POST if key == "share_target.action" else None
        endpoint = _make(resolved, SourceKind.MANIFEST, base_url, f"{key}={value}", method=method)
        if endpoint:
            endpoints.append(endpoint)
    return endpoints


def parse_headers(headers: dict[str, str], base_url: str) -> list[Endpoint]:
    """Mine response headers for service hosts.

    ``Content-Security-Policy`` ``connect-src`` in particular enumerates every
    origin the application is allowed to talk to.

    Args:
        headers: Response headers of the entry page.
        base_url: URL the headers belong to.

    Returns:
        Endpoints extracted from CSP, ``Link`` and vendor headers.
    """
    endpoints: list[Endpoint] = []
    lowered = {key.lower(): value for key, value in headers.items()}

    csp = " ".join(
        value
        for key, value in lowered.items()
        if key in {"content-security-policy", "content-security-policy-report-only"}
    )
    for match in _CSP_SOURCE.finditer(csp):
        for token in match.group(1).split():
            token = token.strip().strip("'\"")
            if token.startswith(("'", "*", "data:", "blob:")) or token in {"self", "none"}:
                continue
            if not token.startswith(("http://", "https://", "ws://", "wss://", "//")):
                continue
            resolved = urlutil.absolutize(base_url, token.replace("*.", ""))
            if not resolved:
                continue
            endpoint = _make(
                resolved, SourceKind.HEADER, base_url, f"CSP {token}", confidence=Confidence.LOW
            )
            if endpoint:
                endpoint.tags = ["csp"]
                endpoints.append(endpoint)

    for header_name in ("link", "x-api-url", "x-backend-url", "x-graphql-url", "location"):
        value = lowered.get(header_name)
        if not value:
            continue
        targets = _LINK_HEADER.findall(value) if header_name == "link" else [value]
        for target in targets:
            resolved = urlutil.absolutize(base_url, target.strip())
            if not resolved:
                continue
            endpoint = _make(resolved, SourceKind.HEADER, base_url, f"{header_name}: {target}")
            if endpoint:
                endpoints.append(endpoint)
    return endpoints


def parse_cookies(cookies: dict[str, str], base_url: str) -> list[Endpoint]:
    """Look for URLs embedded in cookie values.

    Args:
        cookies: Cookie name/value pairs observed on the target.
        base_url: URL the cookies belong to.

    Returns:
        Endpoints for any absolute URL found inside a cookie value.
    """
    endpoints: list[Endpoint] = []
    for name, value in cookies.items():
        if not value:
            continue
        for match in _URL_IN_TEXT.finditer(str(value)):
            endpoint = _make(
                match.group(0),
                SourceKind.COOKIE,
                base_url,
                f"cookie {name}",
                confidence=Confidence.LOW,
            )
            if endpoint:
                endpoint.tags = [f"cookie:{name}"]
                endpoints.append(endpoint)
    return endpoints


def parse_well_known(text: str, url: str) -> list[Endpoint]:
    """Extract endpoints from ``/.well-known/`` documents.

    OpenID configuration documents in particular list every authentication
    endpoint of the identity provider.

    Args:
        text: Document body (JSON or plain text).
        url: URL the document was fetched from.

    Returns:
        Endpoints found in the document.
    """
    endpoints: list[Endpoint] = []
    try:
        data: Any = orjson.loads(text)
    except orjson.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                endpoint = _make(
                    value, SourceKind.WELL_KNOWN, url, f"{key}={value}", confidence=Confidence.HIGH
                )
                if endpoint:
                    if "endpoint" in key.lower() or "uri" in key.lower():
                        endpoint.type = EndpointType.AUTH if "openid" in url else endpoint.type
                    endpoint.tags = [f"key:{key}"]
                    endpoints.append(endpoint)
        return endpoints

    for match in _URL_IN_TEXT.finditer(text):
        endpoint = _make(
            match.group(0), SourceKind.WELL_KNOWN, url, match.group(0), confidence=Confidence.LOW
        )
        if endpoint:
            endpoints.append(endpoint)
    return endpoints
