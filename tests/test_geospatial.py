"""Tests for ArcGIS REST and OGC/GeoServer discovery."""

from __future__ import annotations

import orjson

from endpoint_finder.discovery import arcgis, geoserver
from endpoint_finder.models import EndpointType, SourceKind

ARCGIS_ROOT = "https://gis.example.com/arcgis/rest/services"
MAPSERVER = f"{ARCGIS_ROOT}/City/MapServer"


def test_detect_arcgis_service() -> None:
    detected = arcgis.detect_service(f"{MAPSERVER}/3/query?f=json")
    assert detected == (MAPSERVER, "mapserver")
    assert arcgis.detect_service("https://x.com/api/users") is None


def test_arcgis_service_endpoint_types() -> None:
    image = arcgis.make_service_endpoint(
        f"{ARCGIS_ROOT}/Ortho/ImageServer/exportImage", SourceKind.JAVASCRIPT
    )
    assert image is not None
    assert image.type is EndpointType.IMAGE_SERVICE
    assert image.url.endswith("/ImageServer")

    tiles = arcgis.make_service_endpoint(
        f"{ARCGIS_ROOT}/Base/VectorTileServer/tile/1/2/3.pbf", SourceKind.JAVASCRIPT
    )
    assert tiles is not None
    assert tiles.type is EndpointType.TILE_SERVER


def test_metadata_url() -> None:
    assert arcgis.metadata_url(MAPSERVER) == f"{MAPSERVER}?f=json"


def test_parse_services_catalog() -> None:
    document = orjson.dumps(
        {
            "currentVersion": 10.91,
            "folders": ["Planning"],
            "services": [
                {"name": "City", "type": "MapServer"},
                {"name": "Parcels", "type": "FeatureServer"},
            ],
        }
    ).decode()
    endpoints = arcgis.parse_catalog(document, f"{ARCGIS_ROOT}?f=json")
    urls = {endpoint.url for endpoint in endpoints}
    assert f"{ARCGIS_ROOT}/City/MapServer" in urls
    assert f"{ARCGIS_ROOT}/Parcels/FeatureServer" in urls
    assert f"{ARCGIS_ROOT}/Planning" in urls


def test_parse_service_description_expands_layers_and_operations() -> None:
    document = orjson.dumps(
        {
            "currentVersion": 10.91,
            "serviceDescription": "City base map",
            "layers": [{"id": 0, "name": "Roads"}, {"id": 1, "name": "Buildings"}],
            "singleFusedMapCache": True,
        }
    ).decode()
    endpoints = arcgis.parse_catalog(document, f"{MAPSERVER}?f=json")
    urls = {endpoint.url for endpoint in endpoints}
    assert f"{MAPSERVER}/0" in urls
    assert f"{MAPSERVER}/1/query" in urls
    assert f"{MAPSERVER}/export" in urls
    assert f"{MAPSERVER}/identify" in urls
    assert any("/tile/" in url for url in urls)


def test_is_catalog_document() -> None:
    assert arcgis.is_catalog_document('{"currentVersion": 10.9, "layers": []}')
    assert not arcgis.is_catalog_document('{"hello": "world"}')


# --------------------------------------------------------------------------
# OGC
# --------------------------------------------------------------------------
CAPABILITIES = """<?xml version="1.0" encoding="UTF-8"?>
<WMS_Capabilities version="1.3.0" xmlns="http://www.opengis.net/wms"
                  xmlns:xlink="http://www.w3.org/1999/xlink">
  <Capability>
    <Request>
      <GetMap>
        <DCPType><HTTP><Get>
          <OnlineResource xlink:href="https://geo.example.com/geoserver/ows?SERVICE=WMS&amp;"/>
        </Get></HTTP></DCPType>
      </GetMap>
    </Request>
    <Layer>
      <Layer queryable="1"><Name>topp:states</Name><Title>States</Title></Layer>
      <Layer queryable="1"><Name>topp:roads</Name></Layer>
    </Layer>
  </Capability>
</WMS_Capabilities>"""


def test_detect_ogc_service() -> None:
    assert geoserver.detect_service("https://geo.example.com/geoserver/ows?service=WFS") == "WFS"
    assert geoserver.detect_service("https://geo.example.com/geoserver/wms") == "WMS"
    assert geoserver.detect_service("https://x.com/api/users") is None


def test_service_base_strips_ogc_parameters() -> None:
    url = "https://geo.example.com/geoserver/ows?service=WMS&request=GetMap&layers=a&token=k"
    assert geoserver.service_base(url) == "https://geo.example.com/geoserver/ows?token=k"


def test_capabilities_url() -> None:
    built = geoserver.capabilities_url("https://geo.example.com/geoserver/ows", "WFS")
    assert "service=WFS" in built
    assert "request=GetCapabilities" in built
    assert "version=2.0.0" in built


def test_make_service_endpoint_marks_wmts_as_tiles() -> None:
    endpoint = geoserver.make_service_endpoint(
        "https://geo.example.com/gs/service?SERVICE=WMTS&REQUEST=GetTile", SourceKind.JAVASCRIPT
    )
    assert endpoint is not None
    assert endpoint.type is EndpointType.TILE_SERVER


def test_parse_capabilities() -> None:
    doc_url = "https://geo.example.com/geoserver/ows?service=WMS&request=GetCapabilities"
    endpoints = geoserver.parse_capabilities(CAPABILITIES, doc_url)
    assert endpoints
    assert any(
        endpoint.url.startswith("https://geo.example.com/geoserver/ows") for endpoint in endpoints
    )
    layer_endpoint = next((e for e in endpoints if "layers" in e.tags), None)
    assert layer_endpoint is not None
    assert "topp:states" in layer_endpoint.params
    assert "topp:roads" in layer_endpoint.params


def test_is_capabilities_document() -> None:
    assert geoserver.is_capabilities_document(CAPABILITIES)
    assert not geoserver.is_capabilities_document('{"json": true}')
