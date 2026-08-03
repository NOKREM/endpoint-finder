"""ArcGIS REST service detection and catalogue expansion."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import orjson

from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

#: ArcGIS service suffixes and the endpoint type they map to.
SERVICE_TYPES: dict[str, EndpointType] = {
    "mapserver": EndpointType.ARCGIS,
    "featureserver": EndpointType.ARCGIS,
    "imageserver": EndpointType.IMAGE_SERVICE,
    "sceneserver": EndpointType.ARCGIS,
    "vectortileserver": EndpointType.TILE_SERVER,
    "geometryserver": EndpointType.ARCGIS,
    "gpserver": EndpointType.ARCGIS,
    "geocodeserver": EndpointType.ARCGIS,
    "geodataserver": EndpointType.ARCGIS,
    "globeserver": EndpointType.ARCGIS,
    "streamserver": EndpointType.ARCGIS,
}

#: Operations that exist on virtually every ArcGIS service.
_SERVICE_OPERATIONS: dict[str, tuple[str, ...]] = {
    "mapserver": ("export", "identify", "find", "legend", "layers"),
    "featureserver": ("query", "queryRelatedRecords", "layers"),
    "imageserver": ("exportImage", "identify", "computeStatisticsHistograms"),
    "vectortileserver": ("resources/styles/root.json", "tilemap"),
    "geocodeserver": ("findAddressCandidates", "suggest", "reverseGeocode"),
    "geometryserver": ("project", "buffer", "areasAndLengths"),
}

_SERVICE_RE = re.compile(
    r"/(mapserver|featureserver|imageserver|sceneserver|vectortileserver|geometryserver|"
    r"gpserver|geocodeserver|geodataserver|globeserver|streamserver)(?:/|$)",
    re.IGNORECASE,
)


def detect_service(url: str) -> tuple[str, str] | None:
    """Detect the ArcGIS service root inside a URL.

    Args:
        url: Any URL that may contain an ArcGIS service path.

    Returns:
        A ``(service_root_url, service_kind)`` tuple, or ``None``.
    """
    match = _SERVICE_RE.search(urlsplit(url).path)
    if not match:
        return None
    kind = match.group(1).lower()
    root = urlutil.parent_service_url(url, kind)
    return (root, kind) if root else None


def make_service_endpoint(
    url: str, source: SourceKind, source_url: str | None = None, evidence: str = ""
) -> Endpoint | None:
    """Build the endpoint record for an ArcGIS service root.

    Args:
        url: URL somewhere inside an ArcGIS service.
        source: Where the URL was observed.
        source_url: Artefact the URL came from.
        evidence: Supporting snippet.

    Returns:
        An endpoint for the service root, or ``None`` when the URL is not ArcGIS.
    """
    detected = detect_service(url)
    if detected is None:
        return None
    root, kind = detected
    normalised = urlutil.normalize(root)
    if not normalised:
        return None
    return Endpoint(
        url=normalised,
        method=HttpMethod.GET,
        type=SERVICE_TYPES.get(kind, EndpointType.ARCGIS),
        source=source,
        source_url=source_url,
        evidence=evidence or f"ArcGIS {kind}",
        confidence=Confidence.HIGH,
        tags=[f"arcgis:{kind}"],
    )


def metadata_url(service_root: str) -> str:
    """Return the JSON metadata URL of a service root.

    Args:
        service_root: URL of an ArcGIS service root.

    Returns:
        The same URL with ``?f=json`` appended.
    """
    parts = urlsplit(service_root)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "f=json", ""))


def _endpoint(
    url: str,
    doc_url: str,
    etype: EndpointType,
    evidence: str,
    method: HttpMethod = HttpMethod.GET,
    tags: list[str] | None = None,
) -> Endpoint | None:
    """Helper building a normalised ArcGIS endpoint."""
    normalised = urlutil.normalize(url)
    if not normalised:
        return None
    return Endpoint(
        url=normalised,
        method=method,
        type=etype,
        source=SourceKind.ARCGIS_CATALOG,
        source_url=doc_url,
        evidence=evidence,
        confidence=Confidence.HIGH,
        tags=tags or [],
    )


def parse_catalog(text: str, doc_url: str) -> list[Endpoint]:
    """Expand an ArcGIS REST directory or service metadata document.

    Handles three shapes: a folder/services catalogue, a service description with
    layers, and a layer description.

    Args:
        text: JSON body returned by ``?f=json``.
        doc_url: URL the document was fetched from.

    Returns:
        Endpoints for child services, layers and standard operations.
    """
    try:
        data: Any = orjson.loads(text)
    except orjson.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    endpoints: list[Endpoint] = []
    root = doc_url.split("?")[0].rstrip("/")

    # --- services directory ------------------------------------------------
    for service in data.get("services") or []:
        if not isinstance(service, dict):
            continue
        name = service.get("name")
        kind = str(service.get("type") or "").strip()
        if not isinstance(name, str) or not kind:
            continue
        # Inside a folder listing the name is "Folder/Service"; the folder is
        # already part of ``root`` so only the last segment must be appended.
        service_url = f"{root}/{name.rsplit('/', 1)[-1]}/{kind}"
        endpoint = _endpoint(
            service_url,
            doc_url,
            SERVICE_TYPES.get(kind.lower(), EndpointType.ARCGIS),
            f"catalog service {name} ({kind})",
            tags=[f"arcgis:{kind.lower()}"],
        )
        if endpoint:
            endpoints.append(endpoint)

    for folder in data.get("folders") or []:
        if isinstance(folder, str):
            endpoint = _endpoint(
                f"{root}/{folder}",
                doc_url,
                EndpointType.ARCGIS,
                f"catalog folder {folder}",
                tags=["arcgis:folder"],
            )
            if endpoint:
                endpoints.append(endpoint)

    # --- service description ------------------------------------------------
    detected = detect_service(root)
    if detected:
        service_root, kind = detected
        for layer_key in ("layers", "tables"):
            for layer in data.get(layer_key) or []:
                if not isinstance(layer, dict):
                    continue
                layer_id = layer.get("id")
                if layer_id is None:
                    continue
                layer_name = str(layer.get("name") or "")
                layer_url = f"{service_root}/{layer_id}"
                endpoint = _endpoint(
                    layer_url,
                    doc_url,
                    SERVICE_TYPES.get(kind, EndpointType.ARCGIS),
                    f"layer {layer_id}: {layer_name}",
                    tags=[f"arcgis:{kind}", f"layer:{layer_id}"],
                )
                if endpoint:
                    endpoints.append(endpoint)
                query = _endpoint(
                    f"{service_root}/{layer_id}/query",
                    doc_url,
                    SERVICE_TYPES.get(kind, EndpointType.ARCGIS),
                    f"query operation for layer {layer_id}",
                    tags=[f"arcgis:{kind}", "operation:query"],
                )
                if query:
                    endpoints.append(query)

        for operation in _SERVICE_OPERATIONS.get(kind, ()):
            endpoint = _endpoint(
                f"{service_root}/{operation}",
                doc_url,
                SERVICE_TYPES.get(kind, EndpointType.ARCGIS),
                f"standard {kind} operation",
                tags=[f"arcgis:{kind}", f"operation:{operation}"],
            )
            if endpoint:
                endpoints.append(endpoint)

        if data.get("singleFusedMapCache") or data.get("tileInfo"):
            tile = _endpoint(
                f"{service_root}/tile/{{z}}/{{y}}/{{x}}",
                doc_url,
                EndpointType.TILE_SERVER,
                "cached tile scheme",
                tags=[f"arcgis:{kind}", "operation:tile"],
            )
            if tile:
                endpoints.append(tile)

    logger.debug("arcgis catalog %s expanded into %d endpoints", doc_url, len(endpoints))
    return endpoints


def is_catalog_document(text: str) -> bool:
    """Cheap check that a body looks like ArcGIS REST metadata.

    Args:
        text: Response body.

    Returns:
        ``True`` when the JSON carries ArcGIS specific keys.
    """
    head = text[:2048].lower()
    return (
        '"currentversion"' in head
        or ('"services"' in head and '"folders"' in head)
        or '"servicedescription"' in head
    )
