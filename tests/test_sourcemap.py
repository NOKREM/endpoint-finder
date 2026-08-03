"""Tests for source map parsing and recursive analysis."""

from __future__ import annotations

import orjson

from endpoint_finder.models import SourceKind
from endpoint_finder.parser import sourcemap
from endpoint_finder.parser.jsparser import AnalysisContext

MAP_URL = "https://example.com/static/app.js.map"

DOCUMENT = orjson.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sourceRoot": "",
        "sources": ["src/api.js", "webpack://ignored/x.js", "node_modules/lib/index.js"],
        "sourcesContent": [
            'export const get = () => fetch("/api/v1/secret-report");',
            'fetch("/should/not/matter");',
            'fetch("/node_modules/thing");',
        ],
        "mappings": "",
    }
).decode()


def test_parse_extracts_sources_and_contents() -> None:
    parsed = sourcemap.parse(DOCUMENT, MAP_URL)
    assert parsed is not None
    assert len(parsed.sources) == 3
    assert parsed.has_content


def test_parse_rejects_non_sourcemaps() -> None:
    assert sourcemap.parse("not json", MAP_URL) is None
    assert sourcemap.parse('{"a": 1}', MAP_URL) is None


def test_original_source_urls_skips_bundler_internals() -> None:
    parsed = sourcemap.parse(DOCUMENT, MAP_URL)
    assert parsed is not None
    urls = sourcemap.original_source_urls(parsed)
    assert "https://example.com/static/src/api.js" in urls
    assert not any("webpack" in url for url in urls)
    assert not any("node_modules" in url for url in urls)


def test_analyze_finds_endpoints_in_original_sources(ctx: AnalysisContext) -> None:
    endpoints, parsed = sourcemap.analyze(DOCUMENT, MAP_URL, ctx)
    assert parsed is not None
    urls = {endpoint.url for endpoint in endpoints}
    assert "https://example.com/api/v1/secret-report" in urls
    assert not any("node_modules" in url for url in urls)
    assert all(endpoint.source is SourceKind.SOURCEMAP for endpoint in endpoints)
    assert any("origin:api.js" in endpoint.tags for endpoint in endpoints)


def test_index_map_sections_are_absorbed() -> None:
    index_map = orjson.dumps(
        {
            "version": 3,
            "sections": [
                {
                    "offset": {"line": 0, "column": 0},
                    "map": {
                        "version": 3,
                        "sources": ["a.js"],
                        "sourcesContent": ['fetch("/api/section");'],
                    },
                }
            ],
        }
    ).decode()
    parsed = sourcemap.parse(index_map, MAP_URL)
    assert parsed is not None
    assert parsed.sources == ["a.js"]
