"""Runtime configuration for endpoint-finder.

Settings can be supplied through CLI flags, environment variables prefixed with
``EF_`` or a ``.env`` file. CLI flags always win.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 endpoint-finder/1.0"
)

#: Extensions that are downloaded and parsed for endpoints.
ANALYSABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".map",
        ".json",
        ".geojson",
        ".topojson",
        ".css",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".webmanifest",
    }
)

#: Extensions that never contain endpoints and are skipped during download.
BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".avif",
        ".bmp",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".ogg",
        ".wav",
        ".pdf",
        ".zip",
        ".gz",
        ".br",
        ".wasm",
    }
)

#: Paths fetched as standard, publicly advertised metadata (passive discovery only).
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/manifest.json",
    "/site.webmanifest",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
)

#: Conventional documentation locations checked when ``probe`` is enabled.
SCHEMA_PROBE_PATHS: tuple[str, ...] = (
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api-docs",
    "/api/v1/openapi.json",
    "/graphql",
)


class Settings(BaseSettings):
    """Everything that changes how a scan behaves.

    Attributes:
        target: Root URL that is being analysed.
        depth: Crawl depth; ``0`` analyses only the entry page.
        max_pages: Hard ceiling on HTML pages visited.
        max_assets: Hard ceiling on JS/CSS/JSON assets downloaded.
        concurrency: Number of simultaneous HTTP requests.
        timeout: Per-request timeout in seconds.
        retries: Retry attempts for transient failures.
        render: Whether to drive a headless browser via Playwright.
        interact: Whether the browser should scroll/click to trigger lazy loading.
        probe: Whether to fetch discovered schema documents and conventional doc paths.
    """

    model_config = SettingsConfigDict(
        env_prefix="EF_", env_file=".env", extra="ignore", case_sensitive=False
    )

    target: str = ""

    # --- crawling -------------------------------------------------------
    depth: Annotated[int, Field(ge=0, le=5)] = 1
    max_pages: Annotated[int, Field(ge=1, le=2000)] = 25
    max_assets: Annotated[int, Field(ge=1, le=5000)] = 300
    follow_subdomains: bool = True
    same_origin_only: bool = False
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    exclude_hosts: list[str] = Field(default_factory=list)

    # --- http -----------------------------------------------------------
    concurrency: Annotated[int, Field(ge=1, le=128)] = 16
    timeout: Annotated[float, Field(gt=0, le=300)] = 20.0
    retries: Annotated[int, Field(ge=0, le=10)] = 3
    verify_ssl: bool = True
    http2: bool = True
    max_redirects: Annotated[int, Field(ge=0, le=20)] = 10
    max_body_bytes: Annotated[int, Field(gt=0)] = 8 * 1024 * 1024
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    cookie_file: Path | None = None
    rate_limit_delay: Annotated[float, Field(ge=0)] = 0.0

    # --- browser --------------------------------------------------------
    render: bool = True
    interact: bool = True
    browser: str = "chromium"
    browser_timeout: Annotated[float, Field(gt=0)] = 45.0
    browser_settle: Annotated[float, Field(ge=0)] = 4.0
    browser_headless: bool = True
    max_interactions: Annotated[int, Field(ge=0, le=200)] = 25
    render_pages: Annotated[int, Field(ge=1, le=50)] = 3
    #: Connect to an already-running Chrome over its DevTools endpoint instead of
    #: launching a fresh one. Whatever session that browser holds is reused as-is.
    cdp_url: str | None = None

    # --- discovery ------------------------------------------------------
    probe: bool = True
    guess_schemas: bool = False
    analyse_sourcemaps: bool = True
    keep_unknown: bool = True
    min_confidence: str = "low"
    #: Opt-in active verification: send one safe request per discovered endpoint
    #: to confirm it is live. Off by default - the tool is passive unless asked.
    verify: bool = False

    # --- io -------------------------------------------------------------
    output_dir: Path = Path("output")
    cache_dir: Path = Path(".ef_cache")
    cache_enabled: bool = True
    cache_ttl: int = 3600
    formats: list[str] = Field(default_factory=lambda: ["json", "csv", "html"])
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False

    @field_validator("include", "exclude")
    @classmethod
    def _validate_patterns(cls, value: list[str]) -> list[str]:
        """Ensure user supplied filters compile as regular expressions."""
        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:  # pragma: no cover - defensive
                msg = f"invalid regex filter {pattern!r}: {exc}"
                raise ValueError(msg) from exc
        return value

    @field_validator("formats")
    @classmethod
    def _validate_formats(cls, value: list[str]) -> list[str]:
        """Normalise and validate requested report formats."""
        allowed = {"json", "csv", "html", "md", "markdown", "sqlite", "graph", "pdf", "all"}
        cleaned = [item.strip().lower() for item in value if item.strip()]
        unknown = set(cleaned) - allowed
        if unknown:
            msg = f"unsupported output format(s): {', '.join(sorted(unknown))}"
            raise ValueError(msg)
        if "all" in cleaned:
            return ["json", "csv", "html", "md", "sqlite", "graph", "pdf"]
        return [("md" if item == "markdown" else item) for item in cleaned]

    @property
    def include_patterns(self) -> list[re.Pattern[str]]:
        """Compiled allow-list patterns."""
        return [re.compile(p, re.IGNORECASE) for p in self.include]

    @property
    def exclude_patterns(self) -> list[re.Pattern[str]]:
        """Compiled deny-list patterns."""
        return [re.compile(p, re.IGNORECASE) for p in self.exclude]

    @property
    def host_suffixes(self) -> list[str]:
        """Normalised ``--host`` domain suffixes, empty when unrestricted."""
        from endpoint_finder.parser.urls import normalise_host_suffix

        return [suffix for suffix in map(normalise_host_suffix, self.hosts) if suffix]

    @property
    def exclude_host_suffixes(self) -> list[str]:
        """Normalised ``--exclude-host`` domain suffixes."""
        from endpoint_finder.parser.urls import normalise_host_suffix

        return [suffix for suffix in map(normalise_host_suffix, self.exclude_hosts) if suffix]

    def cookie_records(self) -> list[Any]:
        """Merge ``--cookie`` entries with any ``--cookie-file`` into full records.

        Returns:
            A list of :class:`~endpoint_finder.cookies.CookieRecord`, ready for
            both the HTTP client and the browser context.
        """
        from urllib.parse import urlsplit

        from endpoint_finder.cookies import merge_cookies, parse_cookie_file

        file_records: list[Any] = []
        if self.cookie_file:
            try:
                file_records = parse_cookie_file(self.cookie_file)
            except FileNotFoundError:
                msg = f"cookie file not found: {self.cookie_file}"
                raise ValueError(msg) from None
        host = urlsplit(self.target).hostname or ""
        return merge_cookies(file_records, self.cookies, host)

    def request_headers(self) -> dict[str, str]:
        """Build the default header set used for every HTTP request."""
        base = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        base.update(self.headers)
        return base
