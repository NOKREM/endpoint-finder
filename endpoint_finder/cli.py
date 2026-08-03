"""Typer based command line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer

from endpoint_finder import __version__
from endpoint_finder.config import Settings
from endpoint_finder.logging_setup import console, setup_logging
from endpoint_finder.pipeline import normalise_target, scan
from endpoint_finder.reporting import terminal as term
from endpoint_finder.reporting import write_reports

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        "Passive API endpoint discovery.\n\n"
        "Analyses HTML, JavaScript, CSS, source maps, browser traffic, Swagger/OpenAPI, "
        "GraphQL, ArcGIS REST and OGC services to enumerate a target's endpoints."
    ),
)


def _version_callback(value: bool) -> None:
    """Print the version and exit when ``--version`` is given."""
    if value:
        console.print(f"endpoint-finder {__version__}")
        raise typer.Exit


def _parse_pairs(values: list[str] | None, separator: str = ":") -> dict[str, str]:
    """Parse ``key:value`` CLI arguments into a dictionary.

    Args:
        values: Raw ``key:value`` strings.
        separator: Character splitting key from value.

    Returns:
        The parsed mapping, ignoring malformed entries.
    """
    parsed: dict[str, str] = {}
    for item in values or []:
        if separator not in item:
            continue
        key, value = item.split(separator, 1)
        key = key.strip()
        if key:
            parsed[key] = value.strip()
    return parsed


@app.command()
def main(  # noqa: PLR0913 - a CLI legitimately has many switches
    target: Annotated[str, typer.Argument(help="Target URL, e.g. https://example.com")],
    depth: Annotated[
        int, typer.Option("--depth", "-d", min=0, max=5, help="Crawl depth (0 = entry page only).")
    ] = 1,
    max_pages: Annotated[
        int, typer.Option("--max-pages", help="Maximum HTML pages to visit.")
    ] = 25,
    max_assets: Annotated[
        int, typer.Option("--max-assets", help="Maximum assets to download.")
    ] = 300,
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", min=1, max=128, help="Parallel HTTP requests.")
    ] = 16,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", help="Per-request timeout in seconds.")
    ] = 20.0,
    retries: Annotated[
        int, typer.Option("--retries", min=0, max=10, help="Retry attempts for transient failures.")
    ] = 3,
    render: Annotated[
        bool, typer.Option("--render/--no-render", help="Drive a headless browser (Playwright).")
    ] = True,
    interact: Annotated[
        bool,
        typer.Option("--interact/--no-interact", help="Scroll and click to trigger lazy loading."),
    ] = True,
    render_pages: Annotated[
        int,
        typer.Option(
            "--render-pages",
            min=1,
            max=50,
            help="How many crawled pages to render; XHR traffic differs per page.",
        ),
    ] = 3,
    headful: Annotated[bool, typer.Option("--headful", help="Show the browser window.")] = False,
    browser: Annotated[
        str, typer.Option("--browser", help="chromium | firefox | webkit")
    ] = "chromium",
    cdp_url: Annotated[
        str | None,
        typer.Option(
            "--cdp-url",
            help=(
                "Attach to a Chrome you are already running over its DevTools "
                "endpoint (e.g. http://127.0.0.1:9222) and reuse its session."
            ),
        ),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option(
            "--verify",
            help=(
                "Actively confirm each discovered endpoint with one safe request. "
                "Off by default; never replays POST/PUT/DELETE."
            ),
        ),
    ] = False,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe/--no-probe", help="Fetch referenced schema/service description documents."
        ),
    ] = True,
    guess_schemas: Annotated[
        bool,
        typer.Option("--guess-schemas", help="Also try conventional /swagger.json style paths."),
    ] = False,
    subdomains: Annotated[
        bool,
        typer.Option("--subdomains/--no-subdomains", help="Treat sibling subdomains as in scope."),
    ] = True,
    same_origin: Annotated[
        bool, typer.Option("--same-origin", help="Restrict the crawl to the exact origin.")
    ] = False,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Only keep URLs matching this regex (repeatable)."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Drop URLs matching this regex (repeatable)."),
    ] = None,
    host: Annotated[
        list[str] | None,
        typer.Option(
            "--host",
            help=(
                "Only report endpoints on this domain or its subdomains "
                "(repeatable). Matches the hostname only, unlike --include."
            ),
        ),
    ] = None,
    exclude_host: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude-host",
            help=(
                "Skip this domain and its subdomains entirely - nothing is "
                "fetched from it and nothing is reported (repeatable)."
            ),
        ),
    ] = None,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", "-f", help="json csv html md sqlite graph pdf all (repeatable)."),
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Directory for report files.")
    ] = Path("output"),
    header: Annotated[
        list[str] | None,
        typer.Option("--header", "-H", help="Extra request header 'Name: value' (repeatable)."),
    ] = None,
    cookie: Annotated[
        list[str] | None, typer.Option("--cookie", help="Cookie 'name=value' (repeatable).")
    ] = None,
    cookie_file: Annotated[
        Path | None,
        typer.Option(
            "--cookie-file",
            help="Load a session you established yourself: cookies.txt or a JSON export.",
        ),
    ] = None,
    user_agent: Annotated[
        str | None, typer.Option("--user-agent", "-A", help="Override the User-Agent.")
    ] = None,
    proxy: Annotated[
        str | None, typer.Option("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    ] = None,
    insecure: Annotated[
        bool, typer.Option("--insecure", "-k", help="Do not verify TLS certificates.")
    ] = False,
    cache: Annotated[
        bool, typer.Option("--cache/--no-cache", help="Use the on-disk response cache.")
    ] = True,
    cache_dir: Annotated[Path, typer.Option("--cache-dir", help="Cache location.")] = Path(
        ".ef_cache"
    ),
    min_confidence: Annotated[
        str, typer.Option("--min-confidence", help="low | medium | high")
    ] = "low",
    hide_unknown: Annotated[
        bool, typer.Option("--hide-unknown", help="Drop endpoints that could not be classified.")
    ] = False,
    plain: Annotated[
        bool, typer.Option("--plain", help="Print the compact [TYPE]/METHOD/URL listing.")
    ] = False,
    limit: Annotated[int, typer.Option("--limit", help="Max rows printed per type (0 = all).")] = 0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only print the summary.")] = False,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
) -> None:
    """Scan a target and report every endpoint that can be found passively."""
    logger = setup_logging(verbose=verbose, quiet=quiet)

    try:
        normalised = normalise_target(target)
    except ValueError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        settings = Settings(
            target=normalised,
            depth=depth,
            max_pages=max_pages,
            max_assets=max_assets,
            concurrency=concurrency,
            timeout=timeout,
            retries=retries,
            render=render,
            interact=interact,
            render_pages=render_pages,
            browser_headless=not headful,
            browser=browser,
            cdp_url=cdp_url,
            verify=verify,
            probe=probe,
            guess_schemas=guess_schemas,
            follow_subdomains=subdomains,
            same_origin_only=same_origin,
            include=list(include or []),
            exclude=list(exclude or []),
            hosts=list(host or []),
            exclude_hosts=list(exclude_host or []),
            formats=list(formats or ["json", "csv", "html"]),
            output_dir=output,
            headers=_parse_pairs(header, ":"),
            cookies=_parse_pairs(cookie, "="),
            cookie_file=cookie_file,
            user_agent=user_agent or Settings().user_agent,
            proxy=proxy,
            verify_ssl=not insecure,
            cache_enabled=cache,
            cache_dir=cache_dir,
            min_confidence=min_confidence,
            keep_unknown=not hide_unknown,
            verbose=verbose,
            quiet=quiet,
        )
    except ValueError as exc:
        console.print(f"[red]invalid options:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not quiet:
        console.print(f"[bold cyan]endpoint-finder[/bold cyan] {__version__} → {normalised}\n")

    try:
        result = asyncio.run(scan(settings))
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        raise typer.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001 - report cleanly instead of a traceback
        logger.exception("scan failed")
        console.print(f"[red]scan failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(code=1) from exc

    written = write_reports(result, settings)

    if not quiet:
        if plain:
            term.render_plain(result)
        else:
            term.render_table(result, limit=limit)
        term.render_routes(result, limit=limit)
    term.render_summary(result, list(written))

    if not result.endpoints:
        raise typer.Exit(code=3)


def run() -> None:
    """Entry point used by the console script and ``python -m endpoint_finder``."""
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover - defensive
        sys.exit(130)
