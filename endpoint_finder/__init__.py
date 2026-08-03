"""endpoint-finder: passive API endpoint & service discovery toolkit.

The package is organised in layers::

    net        -> resilient async HTTP transport (retry, cache, error taxonomy)
    parser     -> low level extractors (urls, javascript, sourcemaps, metadata)
    discovery  -> protocol aware detectors (rest, graphql, swagger, arcgis, ogc, ws)
    crawler    -> orchestration of pages, assets and the headless browser
    reporting  -> renderers (json, csv, html, markdown, sqlite, graph, pdf)

The public entry points are :func:`endpoint_finder.pipeline.scan` for library use and
:mod:`endpoint_finder.cli` for command line use.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
