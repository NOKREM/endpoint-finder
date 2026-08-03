"""Opt-in active verification of discovered endpoints.

The tool is passive by default: it reports what the target itself revealed and
never touches the endpoints it finds. ``--verify`` turns on a single, deliberately
safe confirmation request per endpoint so an analyst can see which are actually
live - trading the passive guarantee for that signal, only when explicitly asked.

Two safety rules are absolute here:

* only idempotent verbs are ever sent. A discovered ``POST``/``PUT``/``PATCH``/
  ``DELETE`` is **never** replayed, because doing so could create or destroy data
  on the target. Those endpoints are reported but left unverified.
* a ``HEAD`` is preferred over a ``GET`` so no response body is pulled unless the
  server rejects ``HEAD``.
"""

from __future__ import annotations

import asyncio

from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Endpoint, HttpMethod
from endpoint_finder.net.client import AsyncHttpClient

logger = get_logger(__name__)

#: Verbs that are safe to send during verification (no side effects on the target).
_SAFE_METHODS: frozenset[HttpMethod] = frozenset(
    {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.ANY}
)


def is_verifiable(endpoint: Endpoint) -> bool:
    """Whether an endpoint may be actively verified without risk.

    Args:
        endpoint: Endpoint to test.

    Returns:
        ``True`` only for idempotent HTTP(S) endpoints not already observed live.
    """
    if endpoint.status_code is not None:
        return False  # already seen on the wire during the browser stage
    if not endpoint.url.startswith(("http://", "https://")):
        return False  # WebSocket and other schemes cannot be HEAD-checked
    return endpoint.method in _SAFE_METHODS


async def verify_endpoints(
    client: AsyncHttpClient, endpoints: list[Endpoint], concurrency: int = 8
) -> int:
    """Confirm which endpoints are live, mutating them in place.

    Args:
        client: The shared HTTP client (its retry, backoff and challenge handling
            all apply, so verification stays polite under rate limiting).
        endpoints: The final endpoint list; only safe ones are touched.
        concurrency: Maximum simultaneous verification requests.

    Returns:
        The number of endpoints that were actually probed.
    """
    targets = [endpoint for endpoint in endpoints if is_verifiable(endpoint)]
    if not targets:
        return 0

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _check(endpoint: Endpoint) -> None:
        async with semaphore:
            result = await client.head(endpoint.url)
        if result.error is not None and result.status_code == 0:
            endpoint.tags = sorted({*endpoint.tags, f"verify:{result.error.value}"})
            return
        endpoint.status_code = result.status_code
        if result.content_type and not endpoint.content_type:
            endpoint.content_type = result.content_type
        endpoint.tags = sorted({*endpoint.tags, "verified"})

    await asyncio.gather(*(_check(endpoint) for endpoint in targets))
    live = sum(
        1 for endpoint in targets if endpoint.status_code and 200 <= endpoint.status_code < 400
    )
    logger.info("verified %d endpoint(s): %d live", len(targets), live)
    return len(targets)
