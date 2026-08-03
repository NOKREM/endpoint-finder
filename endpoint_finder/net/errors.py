"""Error taxonomy used to turn transport failures into actionable report entries."""

from __future__ import annotations

import ssl
from enum import StrEnum

import httpx


class ErrorCategory(StrEnum):
    """Normalised failure reasons surfaced in the final report."""

    SSL = "ssl"
    DNS = "dns"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    REDIRECT_LOOP = "redirect_loop"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    FORBIDDEN = "http_403"
    NOT_FOUND = "http_404"
    RATE_LIMITED = "http_429"
    SERVER_ERROR = "http_5xx"
    CLIENT_ERROR = "http_4xx"
    CLOUDFLARE = "cloudflare"
    WAF = "waf"
    TOO_LARGE = "body_too_large"
    DECODE = "decode"
    PROTOCOL = "protocol"
    BROWSER = "browser"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


#: ``(header, needle, vendor)`` triples identifying the protection layer. Detection
#: only: the tool reports what stands in front of the target, it does not try to
#: get past it.
_VENDOR_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("cf-mitigated", "", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("cf-chl-bypass", "", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-block", "", "Sucuri"),
    ("x-iinfo", "", "Imperva/Incapsula"),
    ("x-cdn", "incapsula", "Imperva/Incapsula"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-amzn-waf-action", "", "AWS WAF"),
    ("x-datadome", "", "DataDome"),
    ("x-px-block", "", "PerimeterX"),
    ("server", "awselb", "AWS ELB"),
)

#: Body markers of an interstitial challenge page rather than real content.
#: These must be phrases that only appear when the *whole page* is a challenge or
#: block. A real login/signup page legitimately embeds a Turnstile or captcha
#: widget for its own form, so widget resource URLs (challenges.cloudflare.com,
#: captcha-delivery.com, px-captcha) are deliberately NOT here - keying on them
#: would throw away real content that merely carries a captcha.
_CHALLENGE_MARKERS: tuple[str, ...] = (
    "just a moment...",
    "cf-browser-verification",
    "checking your browser before accessing",
    "attention required! | cloudflare",
    "__cf_chl",
    "cf_chl_opt",
    "enable javascript and cookies to continue",
    "ddos protection by",
    "request unsuccessful. incapsula",
    "access denied | ",
    "you have been blocked",
    "_imperva_",
)


def protection_vendor(headers: dict[str, str] | None, body_head: str = "") -> str | None:
    """Identify the protection or CDN layer in front of a target.

    Args:
        headers: Response headers.
        body_head: First few kilobytes of the body.

    Returns:
        The vendor name, or ``None`` when nothing recognisable is present.
    """
    lowered = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    for header, needle, vendor in _VENDOR_HEADERS:
        value = lowered.get(header)
        if value is None:
            continue
        if not needle or needle in value:
            return vendor
    body = body_head.lower()
    if "cloudflare" in body and any(marker in body for marker in _CHALLENGE_MARKERS):
        return "Cloudflare"
    return None


def is_challenge_page(status_code: int, headers: dict[str, str] | None, body_head: str) -> bool:
    """Whether a response is an interstitial challenge rather than real content.

    A challenge commonly arrives with status 200, so the status code alone is not
    enough to tell that the body is worthless for analysis.

    Args:
        status_code: HTTP status code.
        headers: Response headers.
        body_head: First few kilobytes of the body.

    Returns:
        ``True`` when the body is a challenge or block page.
    """
    body = body_head.lower()
    if any(marker in body for marker in _CHALLENGE_MARKERS):
        return True
    lowered = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    if "challenge" in lowered.get("cf-mitigated", ""):
        return True
    return bool(status_code in (401, 403, 429, 503) and protection_vendor(headers, body_head))


def classify_exception(exc: BaseException) -> ErrorCategory:
    """Map a transport exception onto an :class:`ErrorCategory`.

    Args:
        exc: The exception raised while performing the request.

    Returns:
        The matching category, ``UNKNOWN`` when nothing else fits.
    """
    if isinstance(exc, httpx.TooManyRedirects):
        return ErrorCategory.TOO_MANY_REDIRECTS
    if isinstance(exc, httpx.TimeoutException):
        return ErrorCategory.TIMEOUT
    if isinstance(exc, ssl.SSLError | ssl.SSLCertVerificationError):
        return ErrorCategory.SSL
    if isinstance(exc, httpx.ConnectError):
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            return ErrorCategory.SSL
        if "name or service not known" in text or "getaddrinfo" in text or "nodename" in text:
            return ErrorCategory.DNS
        return ErrorCategory.CONNECTION
    if isinstance(exc, httpx.ProtocolError | httpx.RemoteProtocolError):
        return ErrorCategory.PROTOCOL
    if isinstance(exc, httpx.DecodingError):
        return ErrorCategory.DECODE
    if isinstance(exc, httpx.TransportError):
        return ErrorCategory.CONNECTION
    if isinstance(exc, UnicodeDecodeError):
        return ErrorCategory.DECODE
    return ErrorCategory.UNKNOWN


def classify_response(
    status_code: int, headers: dict[str, str] | None = None, body_head: str = ""
) -> ErrorCategory | None:
    """Classify a completed but unsuccessful response.

    Args:
        status_code: HTTP status code of the response.
        headers: Response headers (case insensitive keys are handled).
        body_head: First few kilobytes of the body, used for challenge detection.

    Returns:
        The failure category, or ``None`` when the response is usable.
    """
    if is_challenge_page(status_code, headers, body_head):
        vendor = protection_vendor(headers, body_head)
        return ErrorCategory.CLOUDFLARE if vendor == "Cloudflare" else ErrorCategory.WAF

    if status_code == 403:
        return ErrorCategory.FORBIDDEN
    if status_code == 404:
        return ErrorCategory.NOT_FOUND
    if status_code == 429:
        return ErrorCategory.RATE_LIMITED
    if 500 <= status_code < 600:
        return ErrorCategory.SERVER_ERROR
    if 400 <= status_code < 500:
        return ErrorCategory.CLIENT_ERROR
    return None


def is_retryable(category: ErrorCategory) -> bool:
    """Whether a failure is worth retrying.

    Args:
        category: Failure category returned by one of the classifiers.

    Returns:
        ``True`` when a retry has a reasonable chance of succeeding.
    """
    return category in {
        ErrorCategory.TIMEOUT,
        ErrorCategory.CONNECTION,
        ErrorCategory.PROTOCOL,
        ErrorCategory.RATE_LIMITED,
        ErrorCategory.SERVER_ERROR,
    }
