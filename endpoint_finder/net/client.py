"""Async HTTP client with retries, disk cache, size limits and error classification."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import random
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

import httpx

from endpoint_finder.config import Settings
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.net.errors import (
    ErrorCategory,
    classify_exception,
    classify_response,
    is_retryable,
    protection_vendor,
)

logger = get_logger(__name__)

#: Upper bound on the automatic slowdown applied when a target pushes back.
MAX_PENALTY_SECONDS = 8.0


@dataclass(slots=True)
class FetchResult:
    """Outcome of a single HTTP fetch.

    Attributes:
        url: Final URL after redirects.
        requested_url: URL originally requested.
        status_code: HTTP status, ``0`` when the request never completed.
        headers: Response headers.
        text: Decoded body, empty when the request failed or the body was skipped.
        content_type: Value of the ``Content-Type`` header without parameters.
        error: Failure category, ``None`` on success.
        message: Human readable failure detail.
        from_cache: Whether the body was served from the local disk cache.
        elapsed: Wall clock seconds spent on the request.
    """

    url: str
    requested_url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    content_type: str = ""
    error: ErrorCategory | None = None
    message: str = ""
    from_cache: bool = False
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        """Whether the response is usable for analysis."""
        return self.error is None and 200 <= self.status_code < 300

    @property
    def size(self) -> int:
        """Body size in bytes (approximated from the decoded text)."""
        return len(self.text.encode("utf-8", "ignore"))


class AsyncHttpClient:
    """Concurrency limited httpx wrapper used by every fetching component.

    Example:
        >>> async with AsyncHttpClient(Settings(target="https://example.com")) as client:
        ...     result = await client.get("https://example.com/robots.txt")
    """

    def __init__(self, settings: Settings) -> None:
        """Create the client.

        Args:
            settings: Active runtime settings.
        """
        self.settings = settings
        self._semaphore = asyncio.Semaphore(settings.concurrency)
        self._client: httpx.AsyncClient | None = None
        self._cache: Any = None
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()
        #: Grows when the target pushes back (challenge, 429, 503) and decays on
        #: success. Being challenged is a signal to slow down, not to try harder.
        self._penalty: float = 0.0
        self.protection: str | None = None
        self.challenges: int = 0

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> Self:
        """Open the underlying transport and cache."""
        limits = httpx.Limits(
            max_connections=self.settings.concurrency * 2,
            max_keepalive_connections=self.settings.concurrency,
        )
        timeout = httpx.Timeout(
            self.settings.timeout,
            connect=min(self.settings.timeout, 10.0),
            read=self.settings.timeout,
        )
        kwargs: dict[str, Any] = {
            "follow_redirects": True,
            "max_redirects": self.settings.max_redirects,
            "verify": self.settings.verify_ssl,
            "timeout": timeout,
            "limits": limits,
            "headers": self.settings.request_headers(),
            "cookies": self._build_cookie_jar(),
        }
        if self.settings.proxy:
            kwargs["proxy"] = self.settings.proxy
        try:
            self._client = httpx.AsyncClient(http2=self.settings.http2, **kwargs)
        except ImportError:  # pragma: no cover - h2 extra missing
            self._client = httpx.AsyncClient(http2=False, **kwargs)
        self._cache = self._open_cache()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the transport and flush the cache."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._cache is not None:
            with contextlib.suppress(Exception):
                self._cache.close()
            self._cache = None

    def add_session_cookies(self, records: list[Any]) -> None:
        """Inject additional cookies into the live client jar.

        Used to share a session harvested from an attached browser with the
        static HTTP side of the scan, so both reuse the same cleared session.

        Args:
            records: Cookie records to add; existing cookies of the same name are
                overwritten.
        """
        if not records or self._client is None:
            return
        for record in records:
            if record.domain:
                self._client.cookies.set(
                    record.name, record.value, domain=record.domain, path=record.path
                )
            else:
                self._client.cookies.set(record.name, record.value)

    def _build_cookie_jar(self) -> httpx.Cookies | None:
        """Build the cookie jar from the merged ``--cookie``/``--cookie-file`` set.

        Returns:
            An httpx cookie jar, or ``None`` when no cookies were supplied.
        """
        records = self.settings.cookie_records()
        if not records:
            return None
        jar = httpx.Cookies()
        for record in records:
            if record.domain:
                jar.set(record.name, record.value, domain=record.domain, path=record.path)
            else:
                jar.set(record.name, record.value)
        return jar

    def _open_cache(self) -> Any:
        """Open the on-disk response cache when enabled."""
        if not self.settings.cache_enabled:
            return None
        try:
            import diskcache

            self.settings.cache_dir.mkdir(parents=True, exist_ok=True)
            return diskcache.Cache(str(self.settings.cache_dir), size_limit=512 * 1024 * 1024)
        except Exception as exc:  # pragma: no cover - cache is best effort
            logger.debug("disk cache unavailable: %s", exc)
            return None

    # ------------------------------------------------------------------
    # public api
    # ------------------------------------------------------------------
    async def get(self, url: str, *, use_cache: bool = True) -> FetchResult:
        """Fetch a URL with retries and caching.

        Args:
            url: Absolute URL to fetch.
            use_cache: Read from and write to the disk cache.

        Returns:
            A :class:`FetchResult` that is always safe to inspect, never raising.
        """
        cache_key = self._cache_key(url)
        if use_cache and self._cache is not None:
            cached = self._cache.get(cache_key)
            if isinstance(cached, dict):
                logger.debug("cache hit %s", url)
                return FetchResult(from_cache=True, **cached)

        result = await self._get_with_retries(url)

        if use_cache and self._cache is not None and result.ok:
            payload = {
                "url": result.url,
                "requested_url": result.requested_url,
                "status_code": result.status_code,
                "headers": result.headers,
                "text": result.text,
                "content_type": result.content_type,
            }
            with contextlib.suppress(Exception):
                self._cache.set(cache_key, payload, expire=self.settings.cache_ttl)
        return result

    async def get_many(self, urls: list[str], *, use_cache: bool = True) -> list[FetchResult]:
        """Fetch many URLs concurrently.

        Args:
            urls: URLs to fetch; duplicates are preserved in the output order.
            use_cache: Forwarded to :meth:`get`.

        Returns:
            Results in the same order as ``urls``.
        """
        tasks = [self.get(url, use_cache=use_cache) for url in urls]
        return await asyncio.gather(*tasks)

    async def head(self, url: str) -> FetchResult:
        """Issue a HEAD request, falling back to GET when HEAD is rejected.

        Args:
            url: Absolute URL to probe.

        Returns:
            A :class:`FetchResult` without a body.
        """
        result = await self._request("HEAD", url)
        if result.status_code in (405, 501):
            return await self.get(url)
        return result

    async def mark_seen(self, url: str) -> bool:
        """Atomically record a URL and report whether it is new.

        Args:
            url: URL to register.

        Returns:
            ``True`` when the URL had not been processed before.
        """
        async with self._lock:
            if url in self._seen:
                return False
            self._seen.add(url)
            return True

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    async def _get_with_retries(self, url: str) -> FetchResult:
        """Perform a GET, retrying transient failures with exponential backoff."""
        attempts = self.settings.retries + 1
        result = FetchResult(url=url, requested_url=url, error=ErrorCategory.UNKNOWN)
        for attempt in range(attempts):
            result = await self._request("GET", url)
            if result.error is None or not is_retryable(result.error):
                return result
            if attempt == attempts - 1:
                break
            delay = self._backoff_delay(attempt, result)
            logger.debug(
                "retry %s/%s for %s in %.1fs (%s)",
                attempt + 1,
                attempts - 1,
                url,
                delay,
                result.error,
            )
            await asyncio.sleep(delay)
        return result

    def _backoff_delay(self, attempt: int, result: FetchResult) -> float:
        """Compute the wait before the next attempt, honouring ``Retry-After``."""
        retry_after = result.headers.get("retry-after") or result.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), 30.0)
            except ValueError:
                pass
        return min(2**attempt + random.uniform(0, 0.5), 15.0)  # noqa: S311

    async def _request(self, method: str, url: str) -> FetchResult:
        """Execute a single request and normalise the outcome."""
        if self._client is None:  # pragma: no cover - defensive
            msg = "AsyncHttpClient must be used as an async context manager"
            raise RuntimeError(msg)

        async with self._semaphore:
            delay = self.settings.rate_limit_delay + self._penalty
            if delay:
                await asyncio.sleep(delay)
            try:
                response = await self._client.request(method, url)
            except Exception as exc:  # noqa: BLE001 - taxonomy handles everything
                failure = classify_exception(exc)
                logger.debug("%s %s failed: %s (%s)", method, url, exc, failure)
                return FetchResult(
                    url=url,
                    requested_url=url,
                    error=failure,
                    message=f"{type(exc).__name__}: {exc}",
                )

            headers = dict(response.headers)
            content_type = (headers.get("content-type") or "").split(";")[0].strip().lower()
            text = ""
            if method != "HEAD":
                text = self._decode(response)

            category = classify_response(response.status_code, headers, text[:4096])
            self._note_pushback(category, headers, text[:4096])
            return FetchResult(
                url=str(response.url),
                requested_url=url,
                status_code=response.status_code,
                headers=headers,
                text=text,
                content_type=content_type,
                error=category,
                message="" if category is None else f"HTTP {response.status_code}",
                elapsed=response.elapsed.total_seconds() if response.elapsed else 0.0,
            )

    def _note_pushback(
        self, category: ErrorCategory | None, headers: dict[str, str], body_head: str
    ) -> None:
        """Record protection layers and slow down when the target pushes back.

        A challenge or a 429 means the target wants fewer requests. The correct
        response is to back off, not to retry harder or disguise the client.

        Args:
            category: Failure category of the response, if any.
            headers: Response headers.
            body_head: Start of the response body.
        """
        if self.protection is None:
            vendor = protection_vendor(headers, body_head)
            if vendor:
                self.protection = vendor
                logger.info("protection layer detected: %s", vendor)

        # Only signals that actually mean "you are sending too much" count. A 5xx
        # is usually one broken endpoint, and treating it as pushback drags the
        # whole scan down for an unrelated failure.
        pushback = category in {
            ErrorCategory.CLOUDFLARE,
            ErrorCategory.WAF,
            ErrorCategory.RATE_LIMITED,
        }
        if pushback:
            self.challenges += 1
            self._penalty = min(max(self._penalty * 2, 0.5), MAX_PENALTY_SECONDS)
            logger.debug("slowing down: penalty now %.1fs", self._penalty)
        elif self._penalty:
            # Recover quickly once the target is answering normally again.
            self._penalty = self._penalty * 0.5 if self._penalty > 0.1 else 0.0

    def _decode(self, response: httpx.Response) -> str:
        """Decode a response body, enforcing the configured size ceiling."""
        raw = response.content
        if len(raw) > self.settings.max_body_bytes:
            raw = raw[: self.settings.max_body_bytes]
        try:
            return raw.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, UnicodeDecodeError):
            return raw.decode("utf-8", errors="replace")

    def _cache_key(self, url: str) -> str:
        """Build a stable cache key for a URL under the current UA."""
        digest = hashlib.sha256(f"{self.settings.user_agent}|{url}".encode()).hexdigest()
        return f"ef:{digest}"
