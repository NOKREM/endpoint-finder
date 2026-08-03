"""Asset queueing, filtering and downloading."""

from __future__ import annotations

from endpoint_finder.config import Settings
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Asset
from endpoint_finder.net.client import AsyncHttpClient, FetchResult
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

#: Content types that are worth parsing even without a telling extension.
TEXTUAL_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "module",
        "text/css",
        "application/json",
        "application/ld+json",
        "application/geo+json",
        "application/manifest+json",
        "text/xml",
        "application/xml",
        "application/xhtml+xml",
        "text/html",
        "text/plain",
        "application/yaml",
        "text/yaml",
        "application/vnd.api+json",
        "application/problem+json",
        "application/wasm+json",
    }
)


def classify_asset(url: str, content_type: str = "") -> str:
    """Classify an asset into a coarse kind.

    Args:
        url: Asset URL.
        content_type: Response content type, when known.

    Returns:
        One of ``js``, ``css``, ``map``, ``json``, ``xml``, ``yaml``, ``html`` or ``other``.
    """
    ext = urlutil.extension(url)
    if ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        return "js"
    if ext == ".map":
        return "map"
    if ext == ".css":
        return "css"
    if ext in {".json", ".geojson", ".topojson", ".webmanifest"}:
        return "json"
    if ext in {".xml", ".rss", ".atom", ".kml", ".wsdl"}:
        return "xml"
    if ext in {".yaml", ".yml"}:
        return "yaml"
    if ext in {".html", ".htm"}:
        return "html"

    lowered = content_type.lower()
    if "javascript" in lowered or "ecmascript" in lowered:
        return "js"
    if "css" in lowered:
        return "css"
    if "json" in lowered:
        return "json"
    if "yaml" in lowered:
        return "yaml"
    if "xml" in lowered:
        return "xml"
    if "html" in lowered:
        return "html"
    return "other"


class AssetQueue:
    """Bounded, deduplicating queue of assets to download."""

    __slots__ = ("_pending", "_queued", "_records", "settings", "target")

    def __init__(self, settings: Settings, target: str) -> None:
        """Create an empty queue.

        Args:
            settings: Active settings, used for scope and ceiling decisions.
            target: Scan target URL.
        """
        self.settings = settings
        self.target = target
        self._queued: set[str] = set()
        self._pending: list[str] = []
        self._records: list[Asset] = []

    def push(self, url: str, referrer: str | None = None, *, force: bool = False) -> bool:
        """Add an asset URL to the queue if it passes every filter.

        Args:
            url: Absolute asset URL.
            referrer: The artefact that referenced it.
            force: Bypass the extension filter (used for source maps and schemas).

        Returns:
            ``True`` when the asset was queued.
        """
        normalised = urlutil.normalize(url)
        if not normalised or normalised in self._queued:
            return False
        if len(self._queued) >= self.settings.max_assets:
            return False
        if urlutil.is_binary_asset(normalised) and not force:
            return False
        if not force and not urlutil.is_analysable(normalised):
            return False
        if not urlutil.matches_filters(
            normalised, self.settings.include_patterns, self.settings.exclude_patterns
        ):
            return False
        # An explicitly excluded host is never worth fetching, not even when the
        # asset is forced (source maps, schema documents). Note the deny list is
        # checked through host_allowed: host_matches treats an empty list as
        # "everything matches", which would reject every asset here.
        if not urlutil.host_allowed(normalised, [], self.settings.exclude_host_suffixes):
            return False
        # Third party bundles frequently host the backend URLs, so out-of-scope
        # assets are kept when they look like application code rather than
        # tracking pixels or vendor styling.
        out_of_scope = not urlutil.same_scope(
            normalised,
            self.target,
            follow_subdomains=self.settings.follow_subdomains,
            same_origin_only=self.settings.same_origin_only,
        )
        if out_of_scope and not force and classify_asset(normalised) not in {"js", "map", "json"}:
            return False
        self._queued.add(normalised)
        self._pending.append(normalised)
        self._records.append(
            Asset(url=normalised, kind=classify_asset(normalised), referrer=referrer)
        )
        return True

    def push_many(self, urls: list[str], referrer: str | None = None) -> int:
        """Queue several assets at once.

        Args:
            urls: Candidate asset URLs.
            referrer: The artefact that referenced them.

        Returns:
            How many assets were actually queued.
        """
        return sum(1 for url in urls if self.push(url, referrer))

    def drain(self) -> list[str]:
        """Take every pending URL, leaving the queue empty.

        Returns:
            The URLs waiting to be downloaded.
        """
        pending, self._pending = self._pending, []
        return pending

    @property
    def has_pending(self) -> bool:
        """Whether anything is waiting to be downloaded."""
        return bool(self._pending)

    @property
    def records(self) -> list[Asset]:
        """Asset records for the final report."""
        return self._records

    def __len__(self) -> int:
        """Total number of distinct assets ever queued."""
        return len(self._queued)


async def download(client: AsyncHttpClient, urls: list[str]) -> list[tuple[str, FetchResult, str]]:
    """Download assets concurrently and classify the results.

    Args:
        client: Shared HTTP client.
        urls: Asset URLs to download.

    Returns:
        ``(url, result, kind)`` triples for every asset, including failures.
    """
    if not urls:
        return []
    results = await client.get_many(urls)
    output: list[tuple[str, FetchResult, str]] = []
    for url, result in zip(urls, results, strict=True):
        kind = classify_asset(result.url or url, result.content_type)
        output.append((url, result, kind))
    return output


def is_textual(result: FetchResult) -> bool:
    """Whether a fetched asset can be parsed as text.

    Args:
        result: Fetch result to inspect.

    Returns:
        ``True`` when the body is textual and non-empty.
    """
    if not result.text.strip():
        return False
    if not result.content_type:
        return True
    return result.content_type in TEXTUAL_CONTENT_TYPES or result.content_type.startswith("text/")
