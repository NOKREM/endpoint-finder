"""Tests for opt-in active endpoint verification."""

from __future__ import annotations

import httpx
import pytest
import respx

from endpoint_finder.config import Settings
from endpoint_finder.models import Endpoint, EndpointType, HttpMethod
from endpoint_finder.net.client import AsyncHttpClient
from endpoint_finder.verify import is_verifiable, verify_endpoints


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (Endpoint(url="https://x.com/a", method=HttpMethod.GET), True),
        (Endpoint(url="https://x.com/a", method=HttpMethod.HEAD), True),
        (Endpoint(url="https://x.com/a", method=HttpMethod.OPTIONS), True),
        (Endpoint(url="https://x.com/a", method=HttpMethod.ANY), True),
        # Mutating verbs must never be replayed.
        (Endpoint(url="https://x.com/a", method=HttpMethod.POST), False),
        (Endpoint(url="https://x.com/a", method=HttpMethod.PUT), False),
        (Endpoint(url="https://x.com/a", method=HttpMethod.DELETE), False),
        (Endpoint(url="https://x.com/a", method=HttpMethod.PATCH), False),
        # Non-HTTP schemes cannot be HEAD-checked.
        (Endpoint(url="wss://x.com/ws", method=HttpMethod.ANY, type=EndpointType.WEBSOCKET), False),
        # Already observed live -> nothing to add.
        (Endpoint(url="https://x.com/a", method=HttpMethod.GET, status_code=200), False),
    ],
)
def test_is_verifiable(endpoint: Endpoint, expected: bool) -> None:
    assert is_verifiable(endpoint) is expected


@respx.mock
async def test_verify_marks_live_endpoints(settings: Settings) -> None:
    respx.head("https://x.com/live").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/json"})
    )
    respx.head("https://x.com/gone").mock(return_value=httpx.Response(404))
    settings.retries = 0

    endpoints = [
        Endpoint(url="https://x.com/live", method=HttpMethod.GET),
        Endpoint(url="https://x.com/gone", method=HttpMethod.GET),
    ]
    async with AsyncHttpClient(settings) as client:
        count = await verify_endpoints(client, endpoints)

    assert count == 2
    live = next(e for e in endpoints if e.url.endswith("/live"))
    assert live.status_code == 200
    assert live.content_type == "application/json"
    assert "verified" in live.tags
    gone = next(e for e in endpoints if e.url.endswith("/gone"))
    assert gone.status_code == 404
    assert "verified" in gone.tags


@respx.mock
async def test_verify_never_sends_mutating_verbs(settings: Settings) -> None:
    post_route = respx.post("https://x.com/create").mock(return_value=httpx.Response(200))
    head_route = respx.head("https://x.com/create").mock(return_value=httpx.Response(200))
    settings.retries = 0

    endpoint = Endpoint(url="https://x.com/create", method=HttpMethod.POST)
    async with AsyncHttpClient(settings) as client:
        count = await verify_endpoints(client, [endpoint])

    # A POST endpoint is left untouched: neither a POST nor a HEAD is sent.
    assert count == 0
    assert post_route.call_count == 0
    assert head_route.call_count == 0
    assert endpoint.status_code is None
    assert "verified" not in endpoint.tags


@respx.mock
async def test_session_cookies_are_shared_into_the_client(settings: Settings) -> None:
    from endpoint_finder.cookies import CookieRecord

    captured: dict[str, str] = {}

    def _record(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers.get("cookie", "")
        return httpx.Response(200, text="ok")

    respx.get("https://example.com/x").mock(side_effect=_record)
    async with AsyncHttpClient(settings) as client:
        client.add_session_cookies(
            [CookieRecord(name="cf_clearance", value="tok", domain="example.com")]
        )
        await client.get("https://example.com/x")
    assert "cf_clearance=tok" in captured["cookie"]


@respx.mock
async def test_verify_records_unreachable(settings: Settings) -> None:
    respx.head("https://x.com/down").mock(side_effect=httpx.ConnectError("no route"))
    settings.retries = 0
    endpoint = Endpoint(url="https://x.com/down", method=HttpMethod.GET)
    async with AsyncHttpClient(settings) as client:
        await verify_endpoints(client, [endpoint])
    assert endpoint.status_code is None
    assert any(tag.startswith("verify:") for tag in endpoint.tags)
