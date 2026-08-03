"""Breadth-first page crawler bounded by depth, page count and scope."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass

from endpoint_finder.config import Settings
from endpoint_finder.crawler.html import PageData, parse
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.net.client import AsyncHttpClient, FetchResult
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)


@dataclass(slots=True)
class CrawledPage:
    """One successfully fetched and parsed page.

    Attributes:
        depth: Distance from the seed URL.
        result: Raw fetch result.
        data: Parsed page content.
    """

    depth: int
    result: FetchResult
    data: PageData


class Spider:
    """Crawl HTML pages of the target within the configured scope.

    Example:
        >>> spider = Spider(client, settings, "https://example.com")
        >>> async for page in spider.crawl():
        ...     print(page.data.title)
    """

    def __init__(self, client: AsyncHttpClient, settings: Settings, target: str) -> None:
        """Create the spider.

        Args:
            client: Shared HTTP client.
            settings: Active settings.
            target: Scan target used for scope decisions.
        """
        self.client = client
        self.settings = settings
        self.target = target
        self.visited: set[str] = set()
        self.failures: list[FetchResult] = []

    def _in_scope(self, url: str) -> bool:
        """Whether a URL may be crawled as a page."""
        if not urlutil.is_html_like(url):
            return False
        if not urlutil.matches_filters(
            url, self.settings.include_patterns, self.settings.exclude_patterns
        ):
            return False
        if not urlutil.host_allowed(
            url, self.settings.host_suffixes, self.settings.exclude_host_suffixes
        ):
            return False
        return urlutil.same_scope(
            url,
            self.target,
            follow_subdomains=self.settings.follow_subdomains,
            same_origin_only=self.settings.same_origin_only,
        )

    async def crawl(self, seeds: list[str] | None = None) -> AsyncIterator[CrawledPage]:
        """Crawl pages breadth first.

        Args:
            seeds: Starting URLs; defaults to the scan target.

        Yields:
            Every successfully fetched page, in discovery order.
        """
        frontier: list[tuple[str, int]] = [
            (url, 0) for url in (seeds or [self.target]) if urlutil.normalize(url)
        ]
        depth_limit = self.settings.depth

        while frontier and len(self.visited) < self.settings.max_pages:
            batch: list[tuple[str, int]] = []
            while frontier and len(batch) < self.settings.concurrency:
                url, depth = frontier.pop(0)
                normalised = urlutil.normalize(url)
                if not normalised or normalised in self.visited:
                    continue
                if len(self.visited) + len(batch) >= self.settings.max_pages:
                    break
                self.visited.add(normalised)
                batch.append((normalised, depth))
            if not batch:
                break

            results = await asyncio.gather(*(self.client.get(url) for url, _ in batch))
            for (url, depth), result in zip(batch, results, strict=True):
                if not result.ok:
                    self.failures.append(result)
                    logger.debug("page fetch failed %s: %s", url, result.error)
                    continue
                served_as_html = "html" in result.content_type or not result.content_type
                if not served_as_html and not result.text.lstrip().startswith("<"):
                    continue
                page = parse(result.text, result.url or url)
                yield CrawledPage(depth=depth, result=result, data=page)

                if depth >= depth_limit:
                    continue
                for link in [*page.anchors, *page.frames]:
                    normalised = urlutil.normalize(link)
                    if not normalised or normalised in self.visited:
                        continue
                    if self._in_scope(normalised):
                        frontier.append((normalised, depth + 1))

    def stats(self) -> dict[str, int]:
        """Return crawl counters.

        Returns:
            Number of visited pages and failures.
        """
        return {"visited": len(self.visited), "failed": len(self.failures)}
