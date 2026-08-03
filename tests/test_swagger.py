"""Tests for OpenAPI/Swagger detection and expansion."""

from __future__ import annotations

import orjson

from endpoint_finder.discovery import swagger
from endpoint_finder.models import EndpointType, HttpMethod

DOC_URL = "https://example.com/docs/openapi.json"

OPENAPI3 = orjson.dumps(
    {
        "openapi": "3.0.1",
        "info": {"title": "Demo API", "version": "1.0"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers", "tags": ["users"]},
                "post": {"operationId": "createUser"},
                "parameters": [{"name": "tenant", "in": "query"}],
            },
            "/users/{id}": {
                "delete": {
                    "operationId": "deleteUser",
                    "parameters": [{"name": "id", "in": "path"}],
                }
            },
        },
    }
).decode()

SWAGGER2 = orjson.dumps(
    {
        "swagger": "2.0",
        "host": "legacy.example.com",
        "basePath": "/api",
        "schemes": ["https"],
        "paths": {"/items": {"get": {"operationId": "getItems"}}},
    }
).decode()

OPENAPI_YAML = """
openapi: 3.0.0
info:
  title: YAML API
servers:
  - url: https://yaml.example.com
paths:
  /ping:
    get:
      operationId: ping
"""


def test_looks_like_swagger() -> None:
    assert swagger.looks_like_swagger("https://x.com/swagger.json")
    assert swagger.looks_like_swagger("https://x.com/v3/api-docs")
    assert swagger.looks_like_swagger("https://x.com/swagger-ui/index.html")
    assert not swagger.looks_like_swagger("https://x.com/api/users")


def test_load_document_rejects_non_openapi() -> None:
    assert swagger.load_document('{"a": 1}') is None
    assert swagger.load_document("just text") is None


def test_expand_openapi3() -> None:
    endpoints = swagger.analyze(OPENAPI3, DOC_URL)
    pairs = {(endpoint.method, endpoint.url) for endpoint in endpoints}
    assert (HttpMethod.GET, "https://api.example.com/v1/users") in pairs
    assert (HttpMethod.POST, "https://api.example.com/v1/users") in pairs
    assert (HttpMethod.DELETE, "https://api.example.com/v1/users/{id}") in pairs
    assert all(endpoint.type is EndpointType.REST for endpoint in endpoints)
    assert any("operationId:listUsers" in endpoint.tags for endpoint in endpoints)
    assert any("api:Demo API" in endpoint.tags for endpoint in endpoints)
    get_users = next(e for e in endpoints if e.method is HttpMethod.GET)
    assert "tenant:query" in get_users.params


def test_expand_swagger2_uses_host_and_basepath() -> None:
    endpoints = swagger.analyze(SWAGGER2, DOC_URL)
    assert [endpoint.url for endpoint in endpoints] == ["https://legacy.example.com/api/items"]


def test_expand_yaml() -> None:
    endpoints = swagger.analyze(OPENAPI_YAML, "https://example.com/openapi.yaml")
    assert [endpoint.url for endpoint in endpoints] == ["https://yaml.example.com/ping"]


def test_candidate_documents() -> None:
    candidates = swagger.candidate_documents("https://example.com/swagger-ui/index.html")
    assert "https://example.com/swagger-ui/swagger.json" in candidates
    assert "https://example.com/swagger-ui/openapi.json" in candidates
