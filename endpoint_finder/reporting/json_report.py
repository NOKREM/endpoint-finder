"""JSON report writer built on orjson."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import orjson

from endpoint_finder.discovery import api as apimod
from endpoint_finder.models import ScanResult


def build(result: ScanResult) -> dict[str, Any]:
    """Build the JSON document for a scan result.

    Args:
        result: Completed scan result.

    Returns:
        A JSON-serialisable dictionary matching the documented report schema.
    """
    return {
        "target": result.target,
        "scan_time": result.scan_time.isoformat(),
        "page_title": result.page_title,
        "scripts": result.stats.scripts,
        "requests": result.stats.requests,
        "stats": result.stats.model_dump(),
        "summary": apimod.summarize(result.endpoints),
        "type_counts": result.type_counts(),
        "technologies": result.technologies,
        "routes": result.routes,
        "protection": result.protection,
        "challenges": result.challenges,
        "endpoints": [
            {
                "url": endpoint.url,
                "method": endpoint.method.value,
                "type": endpoint.type.value,
                "source": endpoint.source.value,
                "source_url": endpoint.source_url,
                "confidence": endpoint.confidence.value,
                "status_code": endpoint.status_code,
                "content_type": endpoint.content_type,
                "params": endpoint.params,
                "tags": endpoint.tags,
                "evidence": endpoint.evidence,
                "discovered_at": endpoint.discovered_at.isoformat(),
            }
            for endpoint in result.endpoints
        ],
        "assets": [asset.model_dump() for asset in result.assets],
        "errors": [
            {**error.model_dump(exclude={"at"}), "at": error.at.isoformat()}
            for error in result.errors
        ],
    }


def write(result: ScanResult, path: Path) -> Path:
    """Write the JSON report.

    Args:
        result: Completed scan result.
        path: Destination file.

    Returns:
        The path that was written.
    """
    payload = orjson.dumps(build(result), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    path.write_bytes(payload)
    return path
