"""WebSocket endpoint discovery from source code and live browser traffic."""

from __future__ import annotations

from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import AnalysisContext, extract_websockets


def from_source(text: str, ctx: AnalysisContext) -> list[Endpoint]:
    """Extract WebSocket endpoints from a JavaScript artefact.

    Args:
        text: Source text to scan.
        ctx: Resolution context.

    Returns:
        WebSocket endpoints declared in the source.
    """
    return extract_websockets(text, ctx)


def from_browser(url: str, page_url: str) -> Endpoint | None:
    """Record a WebSocket connection observed by the headless browser.

    Args:
        url: The ``ws://``/``wss://`` URL the page connected to.
        page_url: The page that opened the socket.

    Returns:
        The endpoint, or ``None`` when the URL is not a WebSocket URL.
    """
    normalised = urlutil.normalize(url)
    if not normalised or not normalised.startswith(("ws://", "wss://")):
        return None
    return Endpoint(
        url=normalised,
        method=HttpMethod.ANY,
        type=EndpointType.WEBSOCKET,
        source=SourceKind.WEBSOCKET,
        source_url=page_url,
        evidence="live WebSocket connection",
        confidence=Confidence.HIGH,
        tags=["observed"],
    )


def upgrade_scheme(http_url: str) -> str:
    """Convert an HTTP(S) URL into its WebSocket equivalent.

    Args:
        http_url: URL using the ``http`` or ``https`` scheme.

    Returns:
        The same URL using ``ws`` or ``wss``.
    """
    if http_url.startswith("https://"):
        return "wss://" + http_url[len("https://") :]
    if http_url.startswith("http://"):
        return "ws://" + http_url[len("http://") :]
    return http_url
