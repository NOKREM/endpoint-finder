"""OGC / GeoServer service detection and GetCapabilities expansion."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from lxml import etree

from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

#: OGC service acronyms understood by the tool.
OGC_SERVICES: tuple[str, ...] = ("WMS", "WMTS", "WFS", "WCS", "CSW", "WPS")

_PATH_MARKERS = (
    "/geoserver",
    "/ows",
    "/wms",
    "/wmts",
    "/wfs",
    "/wcs",
    "/mapserv",
    "/qgis",
    "/cgi-bin",
)

_VERSIONS = {
    "WMS": "1.3.0",
    "WMTS": "1.0.0",
    "WFS": "2.0.0",
    "WCS": "2.0.1",
    "CSW": "2.0.2",
    "WPS": "1.0.0",
}

_SERVICE_IN_QUERY = re.compile(r"[?&]service=([a-z]+)", re.IGNORECASE)


def detect_service(url: str) -> str | None:
    """Detect which OGC service a URL addresses.

    Args:
        url: URL to inspect.

    Returns:
        The service acronym (``WMS``, ``WFS`` ...) or ``None``.
    """
    parts = urlsplit(url)
    params = {key.lower(): value for key, value in parse_qs(parts.query).items()}
    service_values = params.get("service") or []
    for value in service_values:
        if value.upper() in OGC_SERVICES:
            return value.upper()
    path = parts.path.lower()
    for acronym in OGC_SERVICES:
        if f"/{acronym.lower()}" in path:
            return acronym
    if any(marker in path for marker in _PATH_MARKERS):
        return "WMS"
    return None


def service_base(url: str) -> str:
    """Strip OGC query parameters, keeping the service endpoint itself.

    Args:
        url: Full OGC request URL.

    Returns:
        The base service URL without ``SERVICE``/``REQUEST``/``VERSION`` parameters.
    """
    parts = urlsplit(url)
    dropped = {
        "service",
        "request",
        "version",
        "acceptversions",
        "format",
        "layers",
        "layer",
        "bbox",
        "width",
        "height",
        "srs",
        "crs",
        "styles",
        "tilematrix",
        "tilerow",
        "tilecol",
        "tilematrixset",
        "typename",
        "typenames",
        "outputformat",
        "f",
    }
    kept = {
        key: values for key, values in parse_qs(parts.query).items() if key.lower() not in dropped
    }
    query = urlencode(kept, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def capabilities_url(base_url: str, service: str) -> str:
    """Build the ``GetCapabilities`` URL for a service.

    Args:
        base_url: Base service URL.
        service: Service acronym.

    Returns:
        A fully formed GetCapabilities request URL.
    """
    parts = urlsplit(base_url)
    params = dict(parse_qs(parts.query))
    params["service"] = [service.upper()]
    params["request"] = ["GetCapabilities"]
    params["version"] = [_VERSIONS.get(service.upper(), "1.0.0")]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), ""))


def make_service_endpoint(
    url: str, source: SourceKind, source_url: str | None = None, evidence: str = ""
) -> Endpoint | None:
    """Build an endpoint for an OGC service base URL.

    Args:
        url: URL somewhere inside an OGC service.
        source: Where the URL was observed.
        source_url: Artefact the URL came from.
        evidence: Supporting snippet.

    Returns:
        The service endpoint, or ``None`` when the URL is not OGC.
    """
    service = detect_service(url)
    if service is None:
        return None
    normalised = urlutil.normalize(service_base(url))
    if not normalised:
        return None
    etype = EndpointType.TILE_SERVER if service == "WMTS" else EndpointType.GEOSERVER
    return Endpoint(
        url=normalised,
        method=HttpMethod.GET,
        type=etype,
        source=source,
        source_url=source_url,
        evidence=evidence or f"OGC {service}",
        confidence=Confidence.HIGH,
        tags=[f"ogc:{service.lower()}"],
    )


def parse_capabilities(text: str, doc_url: str) -> list[Endpoint]:
    """Extract layers and operation URLs from a GetCapabilities document.

    Args:
        text: XML body of the capabilities document.
        doc_url: URL the document was fetched from.

    Returns:
        Endpoints for every advertised operation plus one tagged endpoint listing
        the published layer names.
    """
    try:
        parser = etree.XMLParser(recover=True, resolve_entities=False, no_network=True)
        root = etree.fromstring(text.encode("utf-8", "ignore"), parser=parser)
    except (etree.XMLSyntaxError, ValueError) as exc:
        logger.debug("capabilities parse failed for %s: %s", doc_url, exc)
        return []
    if root is None:
        return []

    endpoints: list[Endpoint] = []
    service = detect_service(doc_url) or "WMS"

    # Operation endpoints advertised via OnlineResource / xlink:href.
    xlink = "{http://www.w3.org/1999/xlink}href"
    seen: set[str] = set()
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        href = element.get(xlink) or element.get("href")
        if not href:
            continue
        resolved = urlutil.absolutize(doc_url, href)
        normalised = urlutil.normalize(service_base(resolved)) if resolved else None
        if not normalised or normalised in seen:
            continue
        seen.add(normalised)
        operation = _enclosing_operation(element)
        endpoints.append(
            Endpoint(
                url=normalised,
                method=HttpMethod.GET,
                type=EndpointType.TILE_SERVER if service == "WMTS" else EndpointType.GEOSERVER,
                source=SourceKind.CAPABILITIES,
                source_url=doc_url,
                evidence=f"{service} {operation or 'OnlineResource'}",
                confidence=Confidence.HIGH,
                tags=[f"ogc:{service.lower()}"] + ([f"operation:{operation}"] if operation else []),
            )
        )

    layers = _layer_names(root)
    if layers:
        base = urlutil.normalize(service_base(doc_url))
        if base:
            endpoints.append(
                Endpoint(
                    url=base,
                    method=HttpMethod.GET,
                    type=EndpointType.TILE_SERVER if service == "WMTS" else EndpointType.GEOSERVER,
                    source=SourceKind.CAPABILITIES,
                    source_url=doc_url,
                    evidence=f"{len(layers)} published layers",
                    confidence=Confidence.HIGH,
                    params=layers[:100],
                    tags=[f"ogc:{service.lower()}", "layers"],
                )
            )
    logger.debug("capabilities %s: %d endpoints, %d layers", doc_url, len(endpoints), len(layers))
    return endpoints


def _enclosing_operation(element: etree._Element) -> str:
    """Walk up the tree to find the operation an OnlineResource belongs to."""
    node = element.getparent()
    depth = 0
    known = {
        "getmap",
        "getfeature",
        "getcapabilities",
        "getfeatureinfo",
        "gettile",
        "describefeaturetype",
        "getcoverage",
        "describecoverage",
        "transaction",
        "getlegendgraphic",
        "getrecords",
        "execute",
        "describeprocess",
    }
    while node is not None and depth < 8:
        if isinstance(node.tag, str):
            name = etree.QName(node).localname
            lowered = name.lower()
            if lowered in known:
                return name
            operation_attr = node.get("name")
            if operation_attr and operation_attr.lower() in known:
                return operation_attr
        node = node.getparent()
        depth += 1
    return ""


def _layer_names(root: etree._Element) -> list[str]:
    """Collect published layer identifiers from a capabilities document."""
    names: list[str] = []
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        localname = etree.QName(element).localname.lower()
        if localname not in {"name", "identifier"}:
            continue
        parent = element.getparent()
        if parent is None or not isinstance(parent.tag, str):
            continue
        parent_name = etree.QName(parent).localname.lower()
        if parent_name not in {"layer", "featuretype", "coveragesummary", "coverage", "record"}:
            continue
        if element.text and element.text.strip():
            value = element.text.strip()
            if value not in names:
                names.append(value)
    return names


def is_capabilities_document(text: str) -> bool:
    """Cheap check that a body is an OGC capabilities document.

    Args:
        text: Response body.

    Returns:
        ``True`` when the XML root looks like a capabilities response.
    """
    head = text[:1024].lower()
    return "capabilities" in head and "<" in head
