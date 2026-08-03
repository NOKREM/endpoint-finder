"""Tests for cookie file loading and session merging."""

from __future__ import annotations

from pathlib import Path

from endpoint_finder.cookies import CookieRecord, merge_cookies, parse_cookie_file

NETSCAPE = """# Netscape HTTP Cookie File
# comment line
example.com\tFALSE\t/\tTRUE\t1799999999\tsession\tabc123
#HttpOnly_.example.com\tTRUE\t/\tTRUE\t0\tcf_clearance\txyz
malformed line without tabs
"""

JSON_ARRAY = """
[
  {"name": "session", "value": "abc123", "domain": ".example.com", "path": "/", "secure": true},
  {"name": "theme", "value": "dark", "domain": "example.com"},
  {"not": "a cookie"}
]
"""

JSON_FLAT = '{"session": "abc123", "count": 5}'


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_netscape_format(tmp_path: Path) -> None:
    records = parse_cookie_file(_write(tmp_path, "cookies.txt", NETSCAPE))
    by_name = {record.name: record for record in records}
    assert set(by_name) == {"session", "cf_clearance"}
    assert by_name["session"].value == "abc123"
    assert by_name["session"].domain == "example.com"
    assert by_name["session"].secure is True
    # The #HttpOnly_ prefix is a real cookie line, not a comment.
    assert by_name["cf_clearance"].value == "xyz"
    assert by_name["cf_clearance"].domain == "example.com"


def test_parse_json_array(tmp_path: Path) -> None:
    records = parse_cookie_file(_write(tmp_path, "cookies.json", JSON_ARRAY))
    by_name = {record.name: record for record in records}
    assert by_name["session"].domain == "example.com"  # leading dot stripped
    assert by_name["session"].secure is True
    assert by_name["theme"].value == "dark"
    assert "not" not in by_name


def test_parse_flat_json(tmp_path: Path) -> None:
    records = parse_cookie_file(_write(tmp_path, "flat.json", JSON_FLAT))
    by_name = {record.name: record.value for record in records}
    assert by_name == {"session": "abc123", "count": "5"}


def test_parse_empty_file(tmp_path: Path) -> None:
    assert parse_cookie_file(_write(tmp_path, "empty.txt", "   ")) == []


def test_for_playwright_uses_fallback_domain() -> None:
    record = CookieRecord(name="a", value="b")
    assert record.for_playwright("example.com")["domain"] == "example.com"
    with_domain = CookieRecord(name="a", value="b", domain="api.example.com")
    assert with_domain.for_playwright("example.com")["domain"] == "api.example.com"


def test_merge_inline_overrides_file() -> None:
    file_records = [CookieRecord(name="session", value="old", domain="")]
    merged = merge_cookies(file_records, {"session": "new"}, "example.com")
    by_key = {(r.name, r.domain): r for r in merged}
    assert by_key[("session", "")].value == "new"


def test_merge_keeps_distinct_domains() -> None:
    file_records = [
        CookieRecord(name="id", value="1", domain="a.example.com"),
        CookieRecord(name="id", value="2", domain="b.example.com"),
    ]
    merged = merge_cookies(file_records, {}, "example.com")
    assert len(merged) == 2
