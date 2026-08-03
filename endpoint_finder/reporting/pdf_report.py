"""PDF report writer (requires the optional ``reportlab`` dependency)."""

from __future__ import annotations

from pathlib import Path

from endpoint_finder.discovery import api as apimod
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import ScanResult

logger = get_logger(__name__)

MAX_ROWS = 600


def available() -> bool:
    """Whether ``reportlab`` is importable.

    Returns:
        ``True`` when PDF reports can be produced.
    """
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return False
    return True


def write(result: ScanResult, path: Path) -> Path | None:
    """Write a paginated PDF report.

    Args:
        result: Completed scan result.
        path: Destination file.

    Returns:
        The path that was written, or ``None`` when ``reportlab`` is missing.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        logger.info("reportlab not installed - skipping PDF report")
        return None

    styles = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=7, leading=8.5)
    document = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        title=f"endpoint-finder {result.target}",
        author="endpoint-finder",
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    summary = apimod.summarize(result.endpoints)
    story: list[object] = [
        Paragraph(f"Endpoint report — {result.page_title or result.target}", styles["Title"]),
        Paragraph(
            f"{result.target} · scanned {result.scan_time:%Y-%m-%d %H:%M UTC} · "
            f"{result.stats.duration_seconds}s · passive discovery",
            styles["Normal"],
        ),
        Spacer(1, 6 * mm),
        Paragraph(
            f"<b>{summary['total']}</b> endpoints · <b>{summary['routes']}</b> routes · "
            f"<b>{summary['hosts']}</b> hosts · <b>{summary['high_confidence']}</b> high confidence · "
            f"{result.stats.pages} pages · {result.stats.scripts} scripts · "
            f"{result.stats.requests} network requests",
            styles["Normal"],
        ),
        Spacer(1, 4 * mm),
    ]

    counts = result.type_counts()
    if counts:
        breakdown = [["Type", "Count"], *[[name, str(count)] for name, count in counts.items()]]
        table = Table(breakdown, colWidths=[70 * mm, 25 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ced6")),
                    ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ]
            )
        )
        story += [Paragraph("Breakdown by type", styles["Heading2"]), table, Spacer(1, 6 * mm)]

    rows: list[list[object]] = [["Type", "Method", "URL", "Source", "Conf."]]
    for endpoint in result.endpoints[:MAX_ROWS]:
        rows.append(
            [
                Paragraph(endpoint.type.value, cell),
                Paragraph(endpoint.method.value, cell),
                Paragraph(endpoint.url.replace("&", "&amp;").replace("<", "&lt;"), cell),
                Paragraph(endpoint.source.value, cell),
                Paragraph(endpoint.confidence.value, cell),
            ]
        )
    endpoint_table = Table(
        rows, colWidths=[26 * mm, 16 * mm, 165 * mm, 24 * mm, 15 * mm], repeatRows=1
    )
    endpoint_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ced6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
            ]
        )
    )
    story += [Paragraph("Endpoints", styles["Heading2"]), endpoint_table]
    if len(result.endpoints) > MAX_ROWS:
        story.append(
            Paragraph(
                f"… {len(result.endpoints) - MAX_ROWS} more endpoints omitted; see the JSON report.",
                styles["Italic"],
            )
        )

    document.build(story)
    return path
