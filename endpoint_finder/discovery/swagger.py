"""Swagger / OpenAPI detection and schema expansion."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import orjson
import yaml

from endpoint_finder.discovery.classifier import classify
from endpoint_finder.logging_setup import get_logger
from endpoint_finder.models import Confidence, Endpoint, EndpointType, HttpMethod, SourceKind
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

_HTTP_VERBS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

SWAGGER_URL_MARKERS = (
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "/swagger-ui",
    "/swagger/",
    "/api-docs",
    "/apidocs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/redoc",
    "/openapi",
)


def looks_like_swagger(url: str) -> bool:
    """Whether a URL looks like an OpenAPI document or UI.

    Args:
        url: URL to test.

    Returns:
        ``True`` when the URL matches a known Swagger/OpenAPI location.
    """
    lowered = url.lower()
    return any(marker in lowered for marker in SWAGGER_URL_MARKERS)


def load_document(text: str, content_type: str = "") -> dict[str, Any] | None:
    """Parse an OpenAPI document from JSON or YAML.

    Args:
        text: Raw document body.
        content_type: Response content type, used as a parsing hint.

    Returns:
        The parsed document, or ``None`` when it is not an OpenAPI schema.
    """
    data: Any = None
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")) or "json" in content_type:
        try:
            data = orjson.loads(text)
        except orjson.JSONDecodeError:
            data = None
    if data is None:
        try:
            data = yaml.safe_load(text)
        except (yaml.YAMLError, ValueError, RecursionError):
            return None
    if not isinstance(data, dict):
        return None
    if not ({"swagger", "openapi"} & data.keys()) or "paths" not in data:
        return None
    return data


def _server_bases(document: dict[str, Any], doc_url: str) -> list[str]:
    """Compute absolute base URLs the document's paths are relative to."""
    bases: list[str] = []
    parts = urlsplit(doc_url)

    for server in document.get("servers") or []:
        if not isinstance(server, dict):
            continue
        raw = server.get("url")
        if not isinstance(raw, str) or not raw:
            continue
        for name, spec in (server.get("variables") or {}).items():
            if isinstance(spec, dict) and spec.get("default") is not None:
                raw = raw.replace(f"{{{name}}}", str(spec["default"]))
        resolved = urlutil.absolutize(doc_url, raw)
        if resolved:
            bases.append(resolved.rstrip("/"))

    if "swagger" in document:
        host = document.get("host") or parts.netloc
        base_path = document.get("basePath") or ""
        schemes = document.get("schemes") or [parts.scheme or "https"]
        for scheme in schemes:
            if not isinstance(scheme, str) or scheme.lower() not in {"http", "https"}:
                continue
            bases.append(urlunsplit((scheme, str(host), str(base_path).rstrip("/"), "", "")))

    if not bases:
        bases.append(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    unique: list[str] = []
    for base in bases:
        if base and base not in unique:
            unique.append(base)
    return unique


def expand(document: dict[str, Any], doc_url: str) -> list[Endpoint]:
    """Expand every path/operation of an OpenAPI document into endpoints.

    Args:
        document: Parsed OpenAPI/Swagger document.
        doc_url: URL the document was fetched from.

    Returns:
        One endpoint per ``(path, method)`` pair, tagged with the operation id.
    """
    endpoints: list[Endpoint] = []
    bases = _server_bases(document, doc_url)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return endpoints

    title = ""
    info = document.get("info")
    if isinstance(info, dict):
        title = str(info.get("title") or "")

    for path, operations in paths.items():
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        shared_params = _param_names(operations.get("parameters"))
        for verb, operation in operations.items():
            if verb.lower() not in _HTTP_VERBS:
                continue
            if not isinstance(operation, dict):
                operation = {}
            params = shared_params | _param_names(operation.get("parameters"))
            tags = ["source:openapi"]
            if title:
                tags.append(f"api:{title}")
            operation_id = operation.get("operationId")
            if isinstance(operation_id, str) and operation_id:
                tags.append(f"operationId:{operation_id}")
            for tag in operation.get("tags") or []:
                if isinstance(tag, str):
                    tags.append(f"tag:{tag}")
            summary = str(operation.get("summary") or operation.get("description") or "")[:160]

            for base in bases:
                full = urlutil.absolutize(base + "/", path.lstrip("/"))
                normalised = urlutil.normalize(
                    urlutil.strip_template_placeholders(full) if full else ""
                )
                if not normalised:
                    continue
                etype = classify(normalised, hint="openapi")
                if etype in {EndpointType.UNKNOWN, EndpointType.STATIC_JSON}:
                    etype = EndpointType.REST
                endpoints.append(
                    Endpoint(
                        url=normalised,
                        method=HttpMethod(verb.upper()),
                        method_observed=True,
                        type=etype,
                        source=SourceKind.SWAGGER,
                        source_url=doc_url,
                        evidence=summary or f"{verb.upper()} {path}",
                        confidence=Confidence.HIGH,
                        params=sorted(params),
                        tags=sorted(set(tags)),
                    )
                )
    logger.debug("openapi %s expanded into %d endpoints", doc_url, len(endpoints))
    return endpoints


def _param_names(parameters: Any) -> set[str]:
    """Collect parameter names from an OpenAPI ``parameters`` array."""
    names: set[str] = set()
    if not isinstance(parameters, list):
        return names
    for parameter in parameters:
        if isinstance(parameter, dict):
            name = parameter.get("name")
            if isinstance(name, str) and name:
                location = parameter.get("in") or "query"
                names.add(f"{name}:{location}")
    return names


def analyze(text: str, doc_url: str, content_type: str = "") -> list[Endpoint]:
    """Parse and expand an OpenAPI document in one step.

    Args:
        text: Raw document body.
        doc_url: URL the document was fetched from.
        content_type: Response content type hint.

    Returns:
        Expanded endpoints, empty when the body is not an OpenAPI document.
    """
    document = load_document(text, content_type)
    if document is None:
        return []
    return expand(document, doc_url)


def candidate_documents(ui_url: str) -> list[str]:
    """Guess the schema URL behind a Swagger UI page.

    Args:
        ui_url: URL of a ``swagger-ui`` style HTML page.

    Returns:
        Conventional schema locations relative to that UI.
    """
    parts = urlsplit(ui_url)
    directory = parts.path.rsplit("/", 1)[0]
    names = ("swagger.json", "openapi.json", "v1/swagger.json", "swagger/v1/swagger.json")
    candidates: list[str] = []
    for name in names:
        path = f"{directory.rstrip('/')}/{name}"
        candidate = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        normalised = urlutil.normalize(candidate)
        if normalised and normalised not in candidates:
            candidates.append(normalised)
    return candidates
