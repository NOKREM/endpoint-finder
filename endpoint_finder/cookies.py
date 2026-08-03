"""Loading a user established session from a cookie file.

Scanning a target that requires a login - or one whose challenge the user has
already cleared in their own browser - is done by handing the tool the session
the user established themselves. The tool never creates or bypasses that session;
it only reuses what the user provides.

Three shapes are accepted:

* Netscape / Mozilla ``cookies.txt`` (the ``# Netscape HTTP Cookie File`` format),
* a JSON array of cookie objects, as exported by the common browser extensions,
* a flat JSON object ``{"name": "value"}`` for the simplest case.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson

from endpoint_finder.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class CookieRecord:
    """One cookie, in a shape both httpx and Playwright can consume.

    Attributes:
        name: Cookie name.
        value: Cookie value.
        domain: Domain the cookie belongs to, without a leading dot.
        path: Path scope, defaulting to ``/``.
        secure: Whether the cookie is HTTPS-only.
    """

    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False

    def for_playwright(self, fallback_domain: str) -> dict[str, Any]:
        """Render the cookie as a Playwright ``add_cookies`` entry.

        Args:
            fallback_domain: Domain to use when the record carries none.

        Returns:
            A Playwright cookie dictionary.
        """
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain or fallback_domain,
            "path": self.path or "/",
            "secure": self.secure,
        }


def parse_cookie_file(path: Path) -> list[CookieRecord]:
    """Parse a cookie file, auto-detecting its format.

    Args:
        path: Path to the cookie file.

    Returns:
        The parsed cookie records, empty when the file cannot be understood.

    Raises:
        FileNotFoundError: When ``path`` does not exist.
    """
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        return _parse_json(text)
    return _parse_netscape(text)


def _parse_json(text: str) -> list[CookieRecord]:
    """Parse the JSON array or flat-object cookie forms."""
    try:
        data: Any = orjson.loads(text)
    except orjson.JSONDecodeError as exc:
        logger.warning("cookie file is not valid JSON: %s", exc)
        return []

    records: list[CookieRecord] = []
    if isinstance(data, dict):
        for name, value in data.items():
            if isinstance(name, str) and isinstance(value, str | int | float):
                records.append(CookieRecord(name=name, value=str(value)))
        return records

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if not isinstance(name, str) or value is None:
                continue
            records.append(
                CookieRecord(
                    name=name,
                    value=str(value),
                    domain=str(item.get("domain") or "").lstrip("."),
                    path=str(item.get("path") or "/"),
                    secure=bool(item.get("secure", False)),
                )
            )
    return records


def _parse_netscape(text: str) -> list[CookieRecord]:
    """Parse the tab-separated Netscape ``cookies.txt`` format."""
    records: list[CookieRecord] = []
    for raw in text.splitlines():
        line = raw.strip()
        # ``#HttpOnly_`` is a real prefix on otherwise ordinary lines.
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_") :]
        elif not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        domain, _flag, path, secure, _expiry, name, value = fields[:7]
        if not name:
            continue
        records.append(
            CookieRecord(
                name=name,
                value=value,
                domain=domain.lstrip("."),
                path=path or "/",
                secure=secure.strip().upper() == "TRUE",
            )
        )
    return records


def merge_cookies(
    file_records: list[CookieRecord], inline: dict[str, str], target_host: str
) -> list[CookieRecord]:
    """Combine file cookies with ``--cookie`` entries, inline taking precedence.

    Args:
        file_records: Records parsed from a cookie file.
        inline: ``name -> value`` pairs from repeated ``--cookie`` flags.
        target_host: Host to attach inline (domainless) cookies to.

    Returns:
        The merged record list, deduplicated on ``(name, domain)``.
    """
    merged: dict[tuple[str, str], CookieRecord] = {}
    for record in file_records:
        merged[(record.name, record.domain)] = record
    for name, value in inline.items():
        merged[(name, "")] = CookieRecord(name=name, value=value, domain="")
    _ = target_host  # host is applied later, when a concrete request is built
    return list(merged.values())
