"""Report renderers and the dispatcher that writes every requested format."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from endpoint_finder.config import Settings
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import ScanResult
from endpoint_finder.reporting import (
    csv_report,
    graph_report,
    html_report,
    json_report,
    markdown_report,
    pdf_report,
    sqlite_report,
)

logger = get_logger(__name__)

__all__ = [
    "csv_report",
    "graph_report",
    "html_report",
    "json_report",
    "markdown_report",
    "pdf_report",
    "slugify",
    "sqlite_report",
    "write_reports",
]

_UNSAFE = re.compile(r"[^a-z0-9._-]+")


def slugify(target: str) -> str:
    """Turn a target URL into a filesystem safe base name.

    Args:
        target: Scan target URL.

    Returns:
        A lowercase slug such as ``example.com`` or ``example.com_api``.
    """
    parts = urlsplit(target)
    host = (parts.hostname or "scan").lower()
    path = (parts.path or "").strip("/").replace("/", "_")
    slug = f"{host}_{path}" if path else host
    slug = _UNSAFE.sub("-", slug).strip("-._")
    return slug[:80] or "scan"


def write_reports(result: ScanResult, settings: Settings) -> list[Path]:
    """Write every requested report format.

    Args:
        result: Completed scan result.
        settings: Active settings providing the output directory and formats.

    Returns:
        Paths of the files that were written.
    """
    output_dir = Path(settings.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base = slugify(result.target)

    writers = {
        "json": (json_report.write, ".json"),
        "csv": (csv_report.write, ".csv"),
        "html": (html_report.write, ".html"),
        "md": (markdown_report.write, ".md"),
        "sqlite": (sqlite_report.write, ".sqlite3"),
        "graph": (graph_report.write, ".graphml"),
        "pdf": (pdf_report.write, ".pdf"),
    }

    written: list[Path] = []
    for fmt in settings.formats:
        writer = writers.get(fmt)
        if writer is None:
            continue
        func, suffix = writer
        path = output_dir / f"{base}{suffix}"
        try:
            produced = func(result, path)
        except Exception as exc:  # noqa: BLE001 - one bad format must not lose the rest
            logger.warning("could not write %s report: %s", fmt, exc)
            continue
        if produced is not None:
            written.append(produced)
    return written
