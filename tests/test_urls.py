"""Tests for URL normalisation, scoping and candidate filtering."""

from __future__ import annotations

import re

import pytest

from endpoint_finder.parser import urls as u


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://EXAMPLE.com:443/a/b?x=1#frag", "https://example.com/a/b?x=1"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("https://example.com/a/./b/../c", "https://example.com/a/c"),
        ("https://example.com//a///b", "https://example.com/a/b"),
        ("wss://example.com/socket", "wss://example.com/socket"),
        ("ftp://example.com/x", None),
        ("not a url", None),
        ("", None),
    ],
)
def test_normalize(raw: str, expected: str | None) -> None:
    assert u.normalize(raw) == expected


def test_normalize_drops_query_when_asked() -> None:
    assert u.normalize("https://x.com/a?b=1", keep_query=False) == "https://x.com/a"


@pytest.mark.parametrize(
    ("base", "candidate", "expected"),
    [
        ("https://a.com/x/y.js", "/api/v1", "https://a.com/api/v1"),
        ("https://a.com/x/y.js", "./z", "https://a.com/x/z"),
        ("https://a.com/x/y.js", "//cdn.b.com/z.js", "https://cdn.b.com/z.js"),
        ("https://a.com/", "https://c.com/api", "https://c.com/api"),
        ("https://a.com/", "mailto:x@y.z", None),
        ("https://a.com/", "data:text/plain,hi", None),
    ],
)
def test_absolutize(base: str, candidate: str, expected: str | None) -> None:
    assert u.absolutize(base, candidate) == expected


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("a.b.example.com", "example.com"),
        ("example.com", "example.com"),
        ("harita.ibb.gov.tr", "ibb.gov.tr"),
        ("shop.example.co.uk", "example.co.uk"),
        ("127.0.0.1", "127.0.0.1"),
    ],
)
def test_registered_domain(host: str, expected: str) -> None:
    assert u.registered_domain(host) == expected


def test_same_scope() -> None:
    base = "https://example.com/"
    assert u.same_scope("https://api.example.com/v1", base)
    assert not u.same_scope("https://api.example.com/v1", base, follow_subdomains=False)
    assert not u.same_scope("https://evil.com/v1", base)
    assert u.same_scope("https://example.com/x", base, same_origin_only=True)
    assert not u.same_scope("http://example.com/x", base, same_origin_only=True)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("/api/v1/users", True),
        ("https://x.com/a", True),
        ("//cdn.x.com/a.js", True),
        ("/graphql", True),
        ("/", False),
        ("#anchor", False),
        ("text/html", False),
        ("/1.2.3/", False),
        ("javascript:void(0)", False),
        ("/a", False),
    ],
)
def test_is_probably_url(candidate: str, expected: bool) -> None:
    assert u.is_probably_url(candidate) is expected


@pytest.mark.parametrize(
    "fragment",
    [
        # Minified jQuery regex literals that previously became "endpoints".
        "/g;n.parseJSON=function(b){if(a.JSON",
        "/g;m.parseJSON=function(b){",
        "/i,function(a){return a}",
        "/x)return typeof a",
        "/a=>b",
        "/proto/prototype.call",
    ],
)
def test_code_fragments_are_rejected(fragment: str) -> None:
    assert u.is_probably_url(fragment) is False


def test_real_paths_survive_the_code_filter() -> None:
    assert u.is_probably_url("/api/v1/users")
    assert u.is_probably_url("/api/search?q=a&sort=desc")
    assert u.is_probably_url("/shop;jsessionid=ABC123/cart")
    assert u.is_probably_url("/tiles/{z}/{x}/{y}.pbf")


@pytest.mark.parametrize(
    "url",
    [
        "https://./a",
        "https:///a",
        "https://-bad-.com/a",
        "https://a..b.com/x",
    ],
)
def test_normalize_rejects_invalid_hosts(url: str) -> None:
    assert u.normalize(url) is None


def test_normalize_accepts_valid_hosts() -> None:
    assert u.normalize("https://mc.yandex.ru/watch/1") == "https://mc.yandex.ru/watch/1"
    assert u.normalize("http://127.0.0.1:8765/a") == "http://127.0.0.1:8765/a"
    assert u.normalize("http://localhost:3000/api") == "http://localhost:3000/api"
    # A trailing dot is the legal fully-qualified form and is simply dropped.
    assert u.normalize("https://www.mgm.gov.tr.") == "https://www.mgm.gov.tr/"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.com/a/b.js", ".js"),
        ("https://x.com/a/b.min.js?v=1", ".js"),
        ("https://x.com/a/b", ""),
        ("https://x.com/a/b.geojson", ".geojson"),
    ],
)
def test_extension(url: str, expected: str) -> None:
    assert u.extension(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://x.com/cdn-cgi/challenge-platform/h/g/orchestrate/chl_api/v1",
        "https://x.com/cdn-cgi/rum?req=abc",
        "https://x.com/cdn-cgi/l/email-protection",
        "https://x.com/_Incapsula_Resource?SWJIYLWA=5",
        "https://x.com/_vercel/insights/view",
    ],
)
def test_infrastructure_paths_are_recognised(url: str) -> None:
    assert u.is_infrastructure_path(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://x.com/api/v1/users",
        "https://x.com/cdn/assets/app.js",
        "https://x.com/cgi-bin/mapserv",
    ],
)
def test_application_paths_are_not_infrastructure(url: str) -> None:
    assert u.is_infrastructure_path(url) is False


def test_asset_predicates() -> None:
    assert u.is_binary_asset("https://x.com/a.png")
    assert not u.is_binary_asset("https://x.com/a.js")
    assert u.is_analysable("https://x.com/a.map")
    assert u.is_html_like("https://x.com/products")
    assert not u.is_html_like("https://x.com/a.js")


def test_strip_template_placeholders() -> None:
    assert u.strip_template_placeholders("https://x/api/${id}/d") == "https://x/api/:var/d"
    assert u.strip_template_placeholders("https://x/{{a}}/b") == "https://x/:var/b"


def test_clean_candidate() -> None:
    assert u.clean_candidate('"\\/api\\/v1"') == "/api/v1"
    assert u.clean_candidate("/api/x?a=1&amp;b=2") == "/api/x?a=1&b=2"
    assert u.clean_candidate("/api/x'more") == "/api/x"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Prose punctuation that follows a URL inside a comment.
        ("http://api.jquery.com/data/)", "http://api.jquery.com/data/"),
        ("http://cwe.mitre.org/data/601.html)**", "http://cwe.mitre.org/data/601.html"),
        ("https://x.com/a.", "https://x.com/a"),
        ("https://x.com/a,", "https://x.com/a"),
        ("https://x.com/a;", "https://x.com/a"),
        # Balanced brackets belong to the URL and must survive.
        ("https://x.com/wiki/Foo_(bar)", "https://x.com/wiki/Foo_(bar)"),
        ("https://x.com/tiles/{z}/{x}", "https://x.com/tiles/{z}/{x}"),
        ("https://x.com/api?ids[]=1", "https://x.com/api?ids[]=1"),
    ],
)
def test_trailing_punctuation_is_trimmed(raw: str, expected: str) -> None:
    assert u.clean_candidate(raw) == expected


def test_parent_service_url() -> None:
    url = "https://x.com/arcgis/rest/services/Foo/MapServer/3/query?f=json"
    assert (
        u.parent_service_url(url, "MapServer") == "https://x.com/arcgis/rest/services/Foo/MapServer"
    )
    assert u.parent_service_url(url, "FeatureServer") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mgm.gov.tr", "mgm.gov.tr"),
        (".mgm.gov.tr", "mgm.gov.tr"),
        ("*.mgm.gov.tr", "mgm.gov.tr"),
        ("https://www.mgm.gov.tr/a", "www.mgm.gov.tr"),
        ("  EXAMPLE.COM  ", "example.com"),
        ("example.com:8080", "example.com"),
        ("", ""),
    ],
)
def test_normalise_host_suffix(raw: str, expected: str) -> None:
    assert u.normalise_host_suffix(raw) == expected


def test_host_matches_covers_subdomains() -> None:
    suffixes = ["mgm.gov.tr"]
    assert u.host_matches("https://www.mgm.gov.tr/a", suffixes)
    assert u.host_matches("https://servis.mgm.gov.tr/web/alarmlar", suffixes)
    assert u.host_matches("https://mgm.gov.tr/", suffixes)
    assert not u.host_matches("https://notmgm.gov.tr/", suffixes)
    assert not u.host_matches("https://mgm.gov.tr.evil.com/", suffixes)


def test_host_matches_ignores_the_query_string() -> None:
    # The exact trap --include falls into: a tracker carrying the target URL.
    tracker = "https://mc.yandex.com/watch/1?page-url=https%3A%2F%2Fwww.mgm.gov.tr%2F"
    assert not u.host_matches(tracker, ["mgm.gov.tr"])
    assert u.matches_filters(tracker, [re.compile(r"mgm\.gov\.tr")], [])


def test_host_matches_without_suffixes_allows_everything() -> None:
    assert u.host_matches("https://anything.example/", [])


def test_host_allowed_deny_beats_allow() -> None:
    allow = ["example.com"]
    deny = ["cdn.example.com"]
    assert u.host_allowed("https://www.example.com/a", allow, deny)
    assert not u.host_allowed("https://cdn.example.com/a", allow, deny)
    assert not u.host_allowed("https://static.cdn.example.com/a", allow, deny)
    assert not u.host_allowed("https://other.net/a", allow, deny)


def test_host_allowed_deny_only() -> None:
    deny = ["yandex.com"]
    assert u.host_allowed("https://www.example.com/a", [], deny)
    assert not u.host_allowed("https://mc.yandex.com/watch/1", [], deny)
    # The whole-URL trap in reverse: a target URL carrying "yandex" in its query
    # must not be excluded by a host filter.
    assert u.host_allowed("https://example.com/s?q=yandex", [], deny)


def test_matches_filters() -> None:
    include = [re.compile("/api/")]
    exclude = [re.compile("/static/")]
    assert u.matches_filters("https://x.com/api/a", include, [])
    assert not u.matches_filters("https://x.com/b", include, [])
    assert not u.matches_filters("https://x.com/static/a", [], exclude)
