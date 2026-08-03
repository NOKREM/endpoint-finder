"""Tests for every report writer."""

from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

import orjson
import pytest

from endpoint_finder.config import Settings
from endpoint_finder.models import (
    Asset,
    Confidence,
    Endpoint,
    EndpointType,
    HttpMethod,
    ScanError,
    ScanResult,
    ScanStats,
    SourceKind,
)
from endpoint_finder.reporting import (
    csv_report,
    graph_report,
    html_report,
    json_report,
    markdown_report,
    slugify,
    write_reports,
)


@pytest.fixture
def result() -> ScanResult:
    """A small but representative scan result."""
    return ScanResult(
        target="https://example.com",
        page_title="Demo <Portal>",
        stats=ScanStats(pages=2, scripts=5, requests=12, duration_seconds=3.5),
        endpoints=[
            Endpoint(
                url="https://api.example.com/v1/users",
                method=HttpMethod.GET,
                type=EndpointType.REST,
                source=SourceKind.JAVASCRIPT,
                source_url="https://example.com/app.js",
                confidence=Confidence.HIGH,
                params=["page"],
                tags=["rule:fetch"],
                evidence='fetch("/v1/users")',
            ),
            Endpoint(
                url="https://example.com/graphql",
                method=HttpMethod.POST,
                type=EndpointType.GRAPHQL,
                source=SourceKind.NETWORK,
                source_url="https://example.com/",
                status_code=200,
                content_type="application/json",
            ),
        ],
        assets=[Asset(url="https://example.com/app.js", kind="js")],
        errors=[ScanError(url="https://example.com/x", category="http_404", message="HTTP 404")],
        technologies=["React"],
        routes=["https://example.com/dashboard", "https://example.com/map"],
    )


def test_slugify() -> None:
    assert slugify("https://example.com") == "example.com"
    assert slugify("https://example.com/a/b") == "example.com_a_b"
    assert slugify("https://ex ample.com/") == "ex-ample.com"


def test_json_report(result: ScanResult, tmp_path: Path) -> None:
    path = json_report.write(result, tmp_path / "r.json")
    data = orjson.loads(path.read_bytes())
    assert data["target"] == "https://example.com"
    assert data["scripts"] == 5
    assert data["requests"] == 12
    assert len(data["endpoints"]) == 2
    assert data["endpoints"][0]["method"] in {"GET", "POST"}
    assert data["type_counts"]["REST"] == 1
    assert data["summary"]["total"] == 2
    assert data["errors"][0]["category"] == "http_404"


def test_csv_report(result: ScanResult, tmp_path: Path) -> None:
    path = csv_report.write(result, tmp_path / "r.csv")
    with path.open(encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    assert rows[0][:4] == ["URL", "METHOD", "TYPE", "SOURCE"]
    assert len(rows) == 3
    assert rows[1][0] == "https://api.example.com/v1/users"


def test_html_report_is_self_contained(result: ScanResult, tmp_path: Path) -> None:
    path = html_report.write(result, tmp_path / "r.html")
    text = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in text
    assert "Demo &lt;Portal&gt;" in text
    assert "https://api.example.com/v1/users" in text
    assert "http-equiv" not in text
    assert 'src="http' not in text  # no external resources
    assert "prefers-color-scheme" in text


def test_markdown_report(result: ScanResult, tmp_path: Path) -> None:
    path = markdown_report.write(result, tmp_path / "r.md")
    text = path.read_text(encoding="utf-8")
    assert "# Endpoint report" in text
    assert "### REST (1)" in text
    assert "`https://example.com/graphql`" in text


def test_routes_are_reported_separately_from_endpoints(result: ScanResult, tmp_path: Path) -> None:
    data = orjson.loads(json_report.write(result, tmp_path / "r.json").read_bytes())
    assert data["routes"] == ["https://example.com/dashboard", "https://example.com/map"]
    # Routes must not be counted as endpoints.
    assert all(e["url"] not in data["routes"] for e in data["endpoints"])
    assert data["summary"]["total"] == 2

    md = markdown_report.write(result, tmp_path / "r.md").read_text(encoding="utf-8")
    assert "## Client side routes (2)" in md
    assert "`https://example.com/map`" in md

    page = html_report.write(result, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Client side routes (2)" in page
    assert "https://example.com/dashboard" in page


def test_split_routes_keeps_classified_endpoints() -> None:
    from endpoint_finder.discovery import api as apimod

    plain_route = Endpoint(url="https://x.com/map", type=EndpointType.UNKNOWN)
    real_api = Endpoint(url="https://x.com/api/data", type=EndpointType.REST)
    # A route URL that also classified as a real endpoint stays in both lists.
    dual = Endpoint(url="https://x.com/graphql", type=EndpointType.GRAPHQL)

    kept, routes = apimod.split_routes(
        [plain_route, real_api, dual],
        ["https://x.com/map", "https://x.com/graphql"],
    )
    assert plain_route not in kept
    assert real_api in kept
    assert dual in kept
    assert routes == ["https://x.com/graphql", "https://x.com/map"]


def test_split_routes_matches_ignoring_trailing_slash() -> None:
    from endpoint_finder.discovery import api as apimod

    endpoint = Endpoint(url="https://x.com/event-detail/", type=EndpointType.UNKNOWN)
    kept, _ = apimod.split_routes([endpoint], ["https://x.com/event-detail"])
    assert kept == []


def test_graph_report(result: ScanResult, tmp_path: Path) -> None:
    graph = graph_report.build(result)
    assert graph.has_edge("https://example.com/app.js", "https://api.example.com/v1/users")
    path = graph_report.write(result, tmp_path / "r.graphml")
    assert path.read_text(encoding="utf-8").startswith("<?xml")
    top = graph_report.top_sources(result)
    assert top[0][1] >= 1


def test_sqlite_report(result: ScanResult, tmp_path: Path) -> None:
    from endpoint_finder.reporting import sqlite_report

    path = sqlite_report.write(result, tmp_path / "r.sqlite3")
    sqlite_report.write(result, path)  # second run appends
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] == 4
        types = {row[0] for row in connection.execute("SELECT DISTINCT type FROM endpoints")}
        assert types == {"REST", "GraphQL"}
    finally:
        connection.close()


def test_write_reports_dispatch(result: ScanResult, tmp_path: Path) -> None:
    settings = Settings(
        target="https://example.com",
        output_dir=tmp_path / "out",
        formats=["json", "csv", "html", "md", "sqlite", "graph"],
    )
    written = write_reports(result, settings)
    names = {path.suffix for path in written}
    assert {".json", ".csv", ".html", ".md", ".sqlite3", ".graphml"} <= names
    assert all(path.exists() for path in written)
