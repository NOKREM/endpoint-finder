"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from endpoint_finder.config import Settings
from endpoint_finder.models import SourceKind
from endpoint_finder.parser.jsparser import AnalysisContext

TARGET = "https://example.com"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Fast, offline-friendly settings pointing at a temporary directory."""
    return Settings(
        target=TARGET,
        depth=0,
        render=False,
        interact=False,
        probe=False,
        cache_enabled=False,
        retries=0,
        timeout=5.0,
        concurrency=4,
        output_dir=tmp_path / "output",
        cache_dir=tmp_path / "cache",
        formats=["json"],
        quiet=True,
    )


@pytest.fixture
def ctx() -> AnalysisContext:
    """Analysis context anchored at a JavaScript bundle on the target."""
    return AnalysisContext(
        source_url=f"{TARGET}/static/app.js",
        source_kind=SourceKind.JAVASCRIPT,
        target=TARGET,
    )
