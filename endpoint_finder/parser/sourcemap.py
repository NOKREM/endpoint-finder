"""Source map (``.map``) parsing and recursive analysis of original sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import orjson

from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Endpoint, SourceKind
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import AnalysisContext, analyze_text

logger = get_logger(__name__)

MAX_SOURCES = 4000


@dataclass(slots=True)
class SourceMap:
    """Parsed representation of a source map document.

    Attributes:
        url: URL the map was downloaded from.
        sources: Original file names declared by the map.
        contents: ``(name, content)`` pairs for embedded original sources.
        source_root: Optional ``sourceRoot`` prefix.
    """

    url: str
    sources: list[str] = field(default_factory=list)
    contents: list[tuple[str, str]] = field(default_factory=list)
    source_root: str = ""

    @property
    def has_content(self) -> bool:
        """Whether the map embeds original sources."""
        return bool(self.contents)


def parse(text: str, map_url: str) -> SourceMap | None:
    """Parse a source map document.

    Supports both plain maps and index maps (``sections``).

    Args:
        text: Raw ``.map`` body.
        map_url: URL the map was fetched from.

    Returns:
        A :class:`SourceMap`, or ``None`` when the document is not a source map.
    """
    try:
        data: Any = orjson.loads(text)
    except orjson.JSONDecodeError:
        logger.debug("not a valid source map: %s", map_url)
        return None
    if not isinstance(data, dict):
        return None

    result = SourceMap(url=map_url, source_root=str(data.get("sourceRoot") or ""))
    _absorb(data, result)
    for section in data.get("sections") or []:
        if isinstance(section, dict) and isinstance(section.get("map"), dict):
            _absorb(section["map"], result)
    if not result.sources and not result.contents:
        return None
    return result


def _absorb(data: dict[str, Any], result: SourceMap) -> None:
    """Merge one map object (or index-map section) into the result."""
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not isinstance(sources, list):
        return
    for index, name in enumerate(sources[:MAX_SOURCES]):
        if not isinstance(name, str):
            continue
        result.sources.append(name)
        if isinstance(contents, list) and index < len(contents):
            body = contents[index]
            if isinstance(body, str) and body.strip():
                result.contents.append((name, body))


def original_source_urls(smap: SourceMap) -> list[str]:
    """Resolve the map's ``sources`` entries into absolute URLs.

    Useful when the bundler does not inline ``sourcesContent`` and the original
    files are still served (a common misconfiguration).

    Args:
        smap: Parsed source map.

    Returns:
        Absolute URLs of the original sources, webpack-internal paths removed.
    """
    resolved: list[str] = []
    for name in smap.sources:
        if name.startswith(("webpack://", "webpack-internal://", "rollup://", "vite://")):
            continue
        if "node_modules" in name:
            continue
        joined = f"{smap.source_root}{name}" if smap.source_root else name
        absolute = urlutil.absolutize(smap.url, joined)
        normalised = urlutil.normalize(absolute) if absolute else None
        if normalised and normalised not in resolved:
            resolved.append(normalised)
    return resolved


def analyze(
    text: str, map_url: str, ctx: AnalysisContext
) -> tuple[list[Endpoint], SourceMap | None]:
    """Parse a source map and extract endpoints from every embedded source.

    Args:
        text: Raw ``.map`` body.
        map_url: URL the map was fetched from.
        ctx: Analysis context; the source kind is overridden to ``SOURCEMAP``.

    Returns:
        A tuple of discovered endpoints and the parsed map (``None`` if invalid).
    """
    smap = parse(text, map_url)
    if smap is None:
        return [], None

    map_ctx = AnalysisContext(
        source_url=map_url,
        source_kind=SourceKind.SOURCEMAP,
        target=ctx.target,
        follow_subdomains=ctx.follow_subdomains,
        keep_external=ctx.keep_external,
        include=ctx.include,
        exclude=ctx.exclude,
    )

    endpoints: list[Endpoint] = []
    for name, body in smap.contents:
        if "node_modules" in name:
            continue
        for endpoint in analyze_text(body, map_ctx):
            endpoint.tags = sorted({*endpoint.tags, f"origin:{name.rsplit('/', 1)[-1]}"})
            endpoints.append(endpoint)
    logger.debug(
        "sourcemap %s: %d sources, %d endpoints", map_url, len(smap.sources), len(endpoints)
    )
    return endpoints, smap
