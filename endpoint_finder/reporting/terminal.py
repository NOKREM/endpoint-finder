"""Terminal rendering of scan results."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from endpoint_finder.discovery import api as apimod
from endpoint_finder.logging_setup import console
from endpoint_finder.models import EndpointType, ScanResult

_TYPE_STYLE: dict[EndpointType, str] = {
    EndpointType.REST: "bold cyan",
    EndpointType.GRAPHQL: "bold magenta",
    EndpointType.ARCGIS: "bold green",
    EndpointType.GEOSERVER: "bold yellow",
    EndpointType.IMAGE_SERVICE: "green",
    EndpointType.TILE_SERVER: "yellow",
    EndpointType.AUTH: "bold red",
    EndpointType.WEBSOCKET: "bold blue",
    EndpointType.SWAGGER: "bold white",
    EndpointType.STATIC_JSON: "white",
    EndpointType.SOAP: "cyan",
    EndpointType.STREAM: "blue",
    EndpointType.UNKNOWN: "dim",
}

_METHOD_STYLE: dict[str, str] = {
    "GET": "green",
    "POST": "yellow",
    "PUT": "magenta",
    "PATCH": "magenta",
    "DELETE": "red",
    "HEAD": "dim",
    "OPTIONS": "dim",
    "ANY": "blue",
}

SEPARATOR = "-" * 32


def render_plain(result: ScanResult) -> None:
    """Print endpoints in the compact grouped format.

    Args:
        result: Completed scan result.
    """
    for etype, endpoints in sorted(
        result.by_type().items(), key=lambda kv: (-len(kv[1]), kv[0].value)
    ):
        style = _TYPE_STYLE.get(etype, "white")
        for endpoint in endpoints:
            console.print(Text(f"[{etype.value}]", style=style))
            console.print(
                Text(endpoint.method.value, style=_METHOD_STYLE.get(endpoint.method.value, "white"))
            )
            console.print(
                endpoint.url, style="link" if console.is_terminal else None, highlight=False
            )
            console.print(SEPARATOR, style="dim")


def render_table(result: ScanResult, limit: int = 0) -> None:
    """Print endpoints grouped by type as rich tables.

    Args:
        result: Completed scan result.
        limit: Maximum rows per type; ``0`` prints everything.
    """
    for etype, endpoints in sorted(
        result.by_type().items(), key=lambda kv: (-len(kv[1]), kv[0].value)
    ):
        style = _TYPE_STYLE.get(etype, "white")
        table = Table(
            title=f"[{etype.value}]  ({len(endpoints)})",
            title_style=style,
            title_justify="left",
            box=None,
            pad_edge=False,
            show_edge=False,
            expand=False,
        )
        table.add_column("METHOD", style="bold", width=7, no_wrap=True)
        table.add_column("URL", overflow="fold")
        table.add_column("SOURCE", style="dim", width=14, no_wrap=True)
        table.add_column("C", style="dim", width=1, no_wrap=True)

        shown = endpoints if limit <= 0 else endpoints[:limit]
        for endpoint in shown:
            table.add_row(
                Text(
                    endpoint.method.value, style=_METHOD_STYLE.get(endpoint.method.value, "white")
                ),
                endpoint.url,
                endpoint.source.value,
                endpoint.confidence.value[0].upper(),
            )
        console.print(table)
        if limit and len(endpoints) > limit:
            console.print(f"  … {len(endpoints) - limit} more (see the report files)", style="dim")
        console.print()


def render_routes(result: ScanResult, limit: int = 0) -> None:
    """Print the client side routes of a single page application.

    Args:
        result: Completed scan result.
        limit: Maximum rows to print; ``0`` prints everything.
    """
    if not result.routes:
        return
    console.print(
        Text(f"[Client side routes]  ({len(result.routes)})", style="bold white"),
    )
    console.print(
        "  navigable views, not request targets - each was rendered to expose its calls",
        style="dim",
    )
    shown = result.routes if limit <= 0 else result.routes[:limit]
    for route in shown:
        console.print(f"  {route}", highlight=False)
    if limit and len(result.routes) > limit:
        console.print(f"  … {len(result.routes) - limit} more (see the report files)", style="dim")
    console.print()


def render_summary(result: ScanResult, written: list[object] | None = None) -> None:
    """Print the closing summary panel.

    Args:
        result: Completed scan result.
        written: Paths of the report files that were produced.
    """
    summary = apimod.summarize(result.endpoints)
    lines = [
        f"[bold]{result.target}[/bold]",
        f"{result.page_title or '(no title)'}",
        "",
        f"endpoints   : [bold]{summary['total']}[/bold] "
        f"({summary['routes']} routes, {summary['hosts']} hosts, "
        f"{summary['high_confidence']} high confidence)",
        f"pages       : {result.stats.pages}",
        f"scripts     : {result.stats.scripts}",
        f"sourcemaps  : {result.stats.sourcemaps}",
        f"requests    : {result.stats.requests} (browser)",
        *(
            [f"verified    : {result.stats.verified} endpoints probed"]
            if result.stats.verified
            else []
        ),
        f"downloaded  : {result.stats.assets_downloaded} assets, "
        f"{result.stats.bytes_downloaded / 1024:.0f} KiB",
        f"duration    : {result.stats.duration_seconds}s",
    ]
    if result.routes:
        lines.append(f"spa routes  : {len(result.routes)}")
    if result.technologies:
        lines.append(f"tech        : {', '.join(result.technologies[:8])}")
    counts = result.type_counts()
    if counts:
        lines.append("")
        lines.append(" ".join(f"{name}={count}" for name, count in counts.items()))
    if result.errors:
        categories: dict[str, int] = {}
        for error in result.errors:
            categories[error.category] = categories.get(error.category, 0) + 1
        lines.append("")
        lines.append(
            "[yellow]warnings[/yellow]   : "
            + ", ".join(f"{name}×{count}" for name, count in sorted(categories.items()))
        )

    if result.protection:
        lines.append("")
        lines.append(f"protection  : [yellow]{result.protection}[/yellow]")
        if result.challenges:
            lines.append(
                f"[bold yellow]{result.challenges} response(s) were challenges or rate limits[/bold yellow],"
                " not content."
            )
            lines.append(
                "[dim]the scan slowed itself down automatically. if coverage still looks thin:\n"
                "  · pass a session you established yourself:  --cookie cf_clearance=...\n"
                "  · lower the load:  --concurrency 2  and  EF_RATE_LIMIT_DELAY=1\n"
                "challenge solving is out of scope for this tool.[/dim]"
            )

    # A failed browser silently costs every XHR-only endpoint, so it must not be
    # left to blend into the warning tally.
    browser_failure = next((error for error in result.errors if error.category == "browser"), None)
    if browser_failure is not None and result.stats.requests == 0:
        lines.append("")
        lines.append(
            "[bold red]dynamic capture did not run[/bold red] - endpoints that only\n"
            "appear as runtime XHR/fetch calls are missing from this report."
        )
        lines.append(f"[dim]{browser_failure.message[:160]}[/dim]")
        if (
            "Executable doesn't exist" in browser_failure.message
            or "install" in browser_failure.message
        ):
            lines.append("[dim]fix: python -m playwright install chromium[/dim]")
    if written:
        lines.append("")
        lines.append("reports     : " + ", ".join(str(path) for path in written))

    console.print(Panel("\n".join(lines), title="scan summary", border_style="cyan", expand=False))
