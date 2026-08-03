"""SQLite persistence so scans can be diffed and queried over time."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from endpoint_finder.models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    scan_time    TEXT NOT NULL,
    page_title   TEXT,
    pages        INTEGER DEFAULT 0,
    scripts      INTEGER DEFAULT 0,
    requests     INTEGER DEFAULT 0,
    duration     REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS endpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    method       TEXT NOT NULL,
    type         TEXT NOT NULL,
    source       TEXT NOT NULL,
    source_url   TEXT,
    confidence   TEXT,
    status_code  INTEGER,
    content_type TEXT,
    params       TEXT,
    tags         TEXT,
    evidence     TEXT
);
CREATE TABLE IF NOT EXISTS errors (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url       TEXT,
    category  TEXT,
    message   TEXT
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
CREATE INDEX IF NOT EXISTS idx_endpoints_type ON endpoints(type);
"""


def write(result: ScanResult, path: Path) -> Path:
    """Append the scan result to a SQLite database.

    Each run inserts a new row in ``scans``; existing history is preserved so
    consecutive scans of the same target can be compared with plain SQL.

    Args:
        result: Completed scan result.
        path: Destination database file.

    Returns:
        The path that was written.
    """
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        cursor = connection.execute(
            "INSERT INTO scans (target, scan_time, page_title, pages, scripts, requests, duration)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result.target,
                result.scan_time.isoformat(),
                result.page_title,
                result.stats.pages,
                result.stats.scripts,
                result.stats.requests,
                result.stats.duration_seconds,
            ),
        )
        scan_id = cursor.lastrowid
        connection.executemany(
            "INSERT INTO endpoints (scan_id, url, method, type, source, source_url, confidence,"
            " status_code, content_type, params, tags, evidence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    endpoint.url,
                    endpoint.method.value,
                    endpoint.type.value,
                    endpoint.source.value,
                    endpoint.source_url,
                    endpoint.confidence.value,
                    endpoint.status_code,
                    endpoint.content_type,
                    " ".join(endpoint.params),
                    " ".join(endpoint.tags),
                    endpoint.evidence,
                )
                for endpoint in result.endpoints
            ],
        )
        connection.executemany(
            "INSERT INTO errors (scan_id, url, category, message) VALUES (?, ?, ?, ?)",
            [(scan_id, error.url, error.category, error.message) for error in result.errors],
        )
        connection.commit()
    finally:
        connection.close()
    return path
