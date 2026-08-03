"""Rich powered logging and a shared console instance."""

from __future__ import annotations

import logging
from typing import Final

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

EF_THEME: Final = Theme(
    {
        "ef.rest": "bold cyan",
        "ef.graphql": "bold magenta",
        "ef.arcgis": "bold green",
        "ef.geoserver": "bold yellow",
        "ef.ws": "bold blue",
        "ef.auth": "bold red",
        "ef.dim": "dim",
    }
)

console: Final[Console] = Console(theme=EF_THEME, highlight=False, soft_wrap=False)
_LOGGER_NAME: Final = "endpoint_finder"


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure the package logger and return it.

    Args:
        verbose: Emit DEBUG level records including per-request traces.
        quiet: Suppress everything below ERROR.

    Returns:
        The configured ``endpoint_finder`` logger.
    """
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.INFO
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.handlers.clear()
    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_path=verbose,
        show_time=verbose,
        markup=False,
    )
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False

    # Third party libraries are noisy at DEBUG level.
    for noisy in ("httpx", "httpcore", "hpack", "asyncio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger of the package logger.

    Args:
        name: Optional dotted suffix, usually ``__name__``.

    Returns:
        A logger inheriting the package configuration.
    """
    if not name or name == _LOGGER_NAME:
        return logging.getLogger(_LOGGER_NAME)
    suffix = name.split(".")[-1]
    return logging.getLogger(f"{_LOGGER_NAME}.{suffix}")
