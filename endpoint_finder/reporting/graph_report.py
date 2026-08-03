"""Relationship graph: which artefact references which endpoint."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import networkx as nx

from endpoint_finder.models import ScanResult


def build(result: ScanResult) -> nx.DiGraph:
    """Build a directed graph of ``source -> endpoint`` relationships.

    Node attributes carry the kind (``source`` / ``endpoint``), the endpoint type
    and the host, so the graph can be styled directly in Gephi or Cytoscape.

    Args:
        result: Completed scan result.

    Returns:
        The populated :class:`networkx.DiGraph`.
    """
    graph = nx.DiGraph(name=f"endpoint-finder {result.target}")
    graph.add_node(
        result.target,
        kind="target",
        label=urlsplit(result.target).netloc,
        host=urlsplit(result.target).netloc,
    )

    for endpoint in result.endpoints:
        endpoint_host = urlsplit(endpoint.url).hostname or ""
        graph.add_node(
            endpoint.url,
            kind="endpoint",
            label=urlsplit(endpoint.url).path or "/",
            type=endpoint.type.value,
            method=endpoint.method.value,
            confidence=endpoint.confidence.value,
            host=endpoint_host,
            status=endpoint.status_code if endpoint.status_code is not None else -1,
        )
        source = endpoint.source_url or result.target
        if source not in graph:
            graph.add_node(
                source,
                kind="source",
                label=(urlsplit(source).path or "/").rsplit("/", 1)[-1] or urlsplit(source).netloc,
                host=urlsplit(source).hostname or "",
                type=endpoint.source.value,
            )
        graph.add_edge(source, endpoint.url, relation=endpoint.source.value)
    return graph


def write(result: ScanResult, path: Path) -> Path:
    """Write the relationship graph as GraphML.

    Args:
        result: Completed scan result.
        path: Destination file.

    Returns:
        The path that was written.
    """
    nx.write_graphml(build(result), path, encoding="utf-8", prettyprint=True)
    return path


def top_sources(result: ScanResult, limit: int = 10) -> list[tuple[str, int]]:
    """Rank artefacts by how many endpoints they contributed.

    Args:
        result: Completed scan result.
        limit: Maximum number of rows to return.

    Returns:
        ``(source_url, endpoint_count)`` pairs, richest first.
    """
    graph = build(result)
    counts = [
        (node, graph.out_degree(node))
        for node, data in graph.nodes(data=True)
        if data.get("kind") in {"source", "target"}
    ]
    return sorted(counts, key=lambda item: (-item[1], item[0]))[:limit]
