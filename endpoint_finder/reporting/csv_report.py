"""CSV report writer."""

from __future__ import annotations

import csv
from pathlib import Path

from endpoint_finder.models import ScanResult

#: Column order of the generated CSV.
COLUMNS: tuple[str, ...] = (
    "URL",
    "METHOD",
    "TYPE",
    "SOURCE",
    "SOURCE_URL",
    "CONFIDENCE",
    "STATUS",
    "CONTENT_TYPE",
    "PARAMS",
    "TAGS",
)


def write(result: ScanResult, path: Path) -> Path:
    """Write the CSV report.

    Args:
        result: Completed scan result.
        path: Destination file.

    Returns:
        The path that was written.
    """
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(COLUMNS)
        for endpoint in result.endpoints:
            writer.writerow(
                [
                    endpoint.url,
                    endpoint.method.value,
                    endpoint.type.value,
                    endpoint.source.value,
                    endpoint.source_url or "",
                    endpoint.confidence.value,
                    endpoint.status_code if endpoint.status_code is not None else "",
                    endpoint.content_type or "",
                    " ".join(endpoint.params),
                    " ".join(endpoint.tags),
                ]
            )
    return path
