"""Tests for robots, sitemap, manifest, header, cookie and well-known parsing."""

from __future__ import annotations

from endpoint_finder.models import EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import metadata

BASE = "https://example.com/robots.txt"


def test_parse_robots() -> None:
    text = """
    User-agent: *
    Disallow: /admin/api/
    Disallow: /
    Allow: /api/public/
    Sitemap: https://example.com/sitemap.xml
    """
    endpoints, sitemaps = metadata.parse_robots(text, BASE)
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://example.com/admin/api/" in urls
    assert "https://example.com/api/public/" in urls
    assert sitemaps == ["https://example.com/sitemap.xml"]
    assert all(endpoint.source is SourceKind.ROBOTS for endpoint in endpoints)


def test_parse_sitemap_pages_and_index() -> None:
    sitemap_xml = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/api/v1/feed.json</loc></url>
      <url><loc>https://example.com/about</loc></url>
    </urlset>"""
    pages, nested = metadata.parse_sitemap(sitemap_xml, BASE)
    assert "https://example.com/api/v1/feed.json" in pages
    assert nested == []

    index_xml = """<?xml version="1.0"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
    </sitemapindex>"""
    pages, nested = metadata.parse_sitemap(index_xml, BASE)
    assert nested == ["https://example.com/sitemap-1.xml"]
    assert pages == []


def test_parse_sitemap_tolerates_garbage() -> None:
    assert metadata.parse_sitemap("<<<not xml", BASE) == ([], [])


def test_parse_manifest() -> None:
    manifest = """
    {"start_url": "/app/", "scope": "/app",
     "share_target": {"action": "/api/share"},
     "shortcuts": [{"url": "/api/quick"}]}
    """
    endpoints = metadata.parse_manifest(manifest, "https://example.com/manifest.json")
    urls = {endpoint.url: endpoint for endpoint in endpoints}
    assert "https://example.com/api/share" in urls
    assert urls["https://example.com/api/share"].method is HttpMethod.POST
    assert "https://example.com/api/quick" in urls


def test_parse_headers_reads_csp_connect_src() -> None:
    headers = {
        "Content-Security-Policy": "default-src 'self'; connect-src 'self' https://api.example.com https://ws.example.com",
        "Link": "</api/next>; rel=next",
    }
    endpoints = metadata.parse_headers(headers, "https://example.com/")
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://api.example.com/" in urls
    assert "https://example.com/api/next" in urls


def test_parse_cookies() -> None:
    endpoints = metadata.parse_cookies(
        {"cfg": "api=https://api.example.com/v1"}, "https://example.com/"
    )
    assert endpoints
    assert endpoints[0].url == "https://api.example.com/v1"
    assert endpoints[0].source is SourceKind.COOKIE


def test_parse_well_known_openid() -> None:
    document = """
    {"issuer": "https://id.example.com",
     "token_endpoint": "https://id.example.com/oauth2/token",
     "authorization_endpoint": "https://id.example.com/oauth2/authorize"}
    """
    endpoints = metadata.parse_well_known(
        document, "https://example.com/.well-known/openid-configuration"
    )
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://id.example.com/oauth2/token" in urls
    assert any(endpoint.type is EndpointType.AUTH for endpoint in endpoints)
