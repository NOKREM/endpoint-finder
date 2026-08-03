"""HTML parsing: resource extraction, inline scripts and structured data."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from parsel import Selector

from endpoint_finder.logging_setup import get_logger
from endpoint_finder.parser import urls as urlutil

logger = get_logger(__name__)

#: ``(tag, attribute, bucket)`` triples describing every resource reference.
RESOURCE_RULES: tuple[tuple[str, str, str], ...] = (
    ("script", "src", "scripts"),
    ("link", "href", "links"),
    ("iframe", "src", "frames"),
    ("frame", "src", "frames"),
    ("img", "src", "media"),
    ("img", "data-src", "media"),
    ("img", "srcset", "media"),
    ("source", "src", "media"),
    ("source", "srcset", "media"),
    ("video", "src", "media"),
    ("video", "poster", "media"),
    ("audio", "src", "media"),
    ("track", "src", "media"),
    ("embed", "src", "media"),
    ("object", "data", "media"),
    ("a", "href", "anchors"),
    ("area", "href", "anchors"),
    ("form", "action", "forms"),
    ("base", "href", "base"),
    ("use", "href", "media"),
)

#: Attributes commonly used by frameworks to carry endpoints in markup.
#: Only XPath-safe names belong here; colon-prefixed framework bindings such as
#: ``v-bind:src`` are handled separately by :data:`BINDING_ATTRIBUTE`.
DATA_ATTRIBUTES: tuple[str, ...] = (
    "data-url",
    "data-src",
    "data-href",
    "data-api",
    "data-api-url",
    "data-endpoint",
    "data-action",
    "data-target-url",
    "data-service",
    "data-remote",
    "data-ajax-url",
    "data-json",
    "data-config",
    "data-settings",
    "hx-get",
    "hx-post",
    "hx-put",
    "hx-delete",
    "hx-patch",
    "ng-src",
    "ng-href",
    "formaction",
)

#: Vue/Alpine style bindings whose attribute names are not valid XPath names.
BINDING_ATTRIBUTE = re.compile(
    r"""(?:v-bind)?:(?:src|href|action|url)\s*=\s*["']([^"'<>]{2,400})["']"""
)


@dataclass(slots=True)
class PageData:
    """Everything extracted from a single HTML document.

    Attributes:
        url: URL of the page.
        title: Document title.
        base: Effective base URL after honouring ``<base href>``.
        scripts: Absolute URLs of external scripts.
        inline_scripts: Bodies of inline ``<script>`` elements.
        links: Absolute URLs from ``<link>`` (stylesheets, manifests, preloads).
        frames: Absolute URLs of iframes and frames.
        media: Absolute URLs of media and object resources.
        anchors: Absolute URLs of in-document links.
        forms: ``(action_url, method)`` pairs.
        data_urls: URLs found in framework data attributes.
        inline_styles: Bodies of inline ``<style>`` elements.
        json_blobs: Bodies of JSON-ish ``<script type="application/...">`` blocks.
        meta_urls: URLs from meta refresh and open-graph style tags.
        generators: Values of ``<meta name="generator">`` and similar fingerprints.
    """

    url: str
    title: str = ""
    base: str = ""
    scripts: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    frames: list[str] = field(default_factory=list)
    media: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)
    forms: list[tuple[str, str]] = field(default_factory=list)
    data_urls: list[str] = field(default_factory=list)
    inline_styles: list[str] = field(default_factory=list)
    json_blobs: list[str] = field(default_factory=list)
    meta_urls: list[str] = field(default_factory=list)
    generators: list[str] = field(default_factory=list)

    def all_resources(self) -> list[str]:
        """Every referenced URL, deduplicated and order preserving."""
        seen: set[str] = set()
        result: list[str] = []
        for bucket in (
            self.scripts,
            self.links,
            self.frames,
            self.media,
            self.data_urls,
            self.meta_urls,
        ):
            for item in bucket:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
        return result


def _resolve(base: str, value: str) -> str | None:
    """Resolve and normalise one attribute value."""
    candidate = urlutil.clean_candidate(value)
    if not candidate or candidate.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return None
    resolved = urlutil.absolutize(base, candidate)
    return urlutil.normalize(resolved) if resolved else None


def _srcset_urls(value: str) -> list[str]:
    """Split a ``srcset`` attribute into individual URLs."""
    urls: list[str] = []
    for part in value.split(","):
        candidate = part.strip().split(" ")[0].strip()
        if candidate:
            urls.append(candidate)
    return urls


def parse(html: str, page_url: str) -> PageData:
    """Parse an HTML document into a :class:`PageData` record.

    Args:
        html: Raw HTML source.
        page_url: URL the document was fetched from.

    Returns:
        A fully populated :class:`PageData`; malformed markup is tolerated.
    """
    page = PageData(url=page_url, base=page_url)
    if not html.strip():
        return page

    try:
        selector = Selector(text=html)
    except (ValueError, TypeError) as exc:  # pragma: no cover - parsel is very tolerant
        logger.debug("html parse failed for %s: %s", page_url, exc)
        return page

    title = selector.xpath("//title/text()").get()
    page.title = (title or "").strip()

    base_href = selector.xpath("//base/@href").get()
    if base_href:
        resolved_base = urlutil.absolutize(page_url, base_href.strip())
        if resolved_base:
            page.base = resolved_base

    buckets: dict[str, list[str]] = {
        "scripts": page.scripts,
        "links": page.links,
        "frames": page.frames,
        "media": page.media,
        "anchors": page.anchors,
        "base": [],
    }

    for tag, attribute, bucket in RESOURCE_RULES:
        try:
            raw_values = selector.xpath(f"//{tag}/@{attribute}").getall()
        except ValueError:  # pragma: no cover - guards against exotic markup
            continue
        for raw in raw_values:
            values = _srcset_urls(raw) if attribute == "srcset" else [raw]
            for value in values:
                resolved = _resolve(page.base, value)
                if not resolved:
                    continue
                if bucket == "forms":
                    continue
                target = buckets.get(bucket)
                if target is not None and resolved not in target:
                    target.append(resolved)

    for form in selector.xpath("//form"):
        action = form.xpath("@action").get() or page.base
        method = (form.xpath("@method").get() or "GET").upper()
        resolved = _resolve(page.base, action)
        if resolved:
            page.forms.append((resolved, method if method in {"GET", "POST"} else "GET"))

    for attribute in DATA_ATTRIBUTES:
        try:
            raw_values = selector.xpath(f"//*[@{attribute}]/@{attribute}").getall()
        except ValueError:  # pragma: no cover - defensive
            continue
        for raw in raw_values:
            resolved = _resolve(page.base, raw)
            if resolved and resolved not in page.data_urls:
                page.data_urls.append(resolved)

    for match in BINDING_ATTRIBUTE.finditer(html):
        resolved = _resolve(page.base, match.group(1))
        if resolved and resolved not in page.data_urls:
            page.data_urls.append(resolved)

    for script in selector.xpath("//script"):
        script_type = (script.xpath("@type").get() or "").lower()
        body = script.xpath("string(.)").get() or ""
        if not body.strip():
            continue
        if script_type in {
            "application/json",
            "application/ld+json",
            "importmap",
            "speculationrules",
        }:
            page.json_blobs.append(body)
        else:
            page.inline_scripts.append(body)

    page.inline_styles = [
        body for body in selector.xpath("//style/text()").getall() if body.strip()
    ]

    for content in selector.xpath("//meta[@http-equiv]/@content").getall():
        if "url=" in content.lower():
            candidate = content.lower().split("url=", 1)[1]
            resolved = _resolve(page.base, candidate)
            if resolved:
                page.meta_urls.append(resolved)
    for content in selector.xpath(
        "//meta[@property='og:url' or @property='og:image' or @name='msapplication-config']/@content"
    ).getall():
        resolved = _resolve(page.base, content)
        if resolved:
            page.meta_urls.append(resolved)

    page.generators = [
        value.strip()
        for value in selector.xpath(
            "//meta[@name='generator' or @name='application-name' or @name='framework']/@content"
        ).getall()
        if value.strip()
    ]
    return page


#: Distinctive strings that only appear inside a framework's own bundle. Generic
#: identifiers (``createElement``, ``render``) are deliberately absent: they are
#: plain DOM APIs and would fingerprint every site as React.
SOURCE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "React": (
        "__REACT_DEVTOOLS_GLOBAL_HOOK__",
        "ReactCurrentDispatcher",
        "ReactCurrentOwner",
        "react-dom",
        "useLayoutEffect",
        "__reactFiber$",
    ),
    "Angular": (
        "@angular/core",
        "platformBrowserDynamic",
        "ɵɵdefineComponent",
        "ɵɵdefineInjectable",
        "NgModule",
        "ng-version",
    ),
    "Vue": ("__VUE_DEVTOOLS_GLOBAL_HOOK__", "vue-router", "__vueParentComponent"),
    "Svelte": ("svelte/internal", "$$invalidate"),
    "Next.js": ("__NEXT_DATA__", "next/dist/client"),
    "Nuxt": ("__NUXT__", "nuxt-link"),
    "zone.js": ("Zone.__load_patch", "zone.js"),
    "RxJS": ("rxjs/internal", "BehaviorSubject"),
    "jQuery": ("jQuery.fn.jquery", "jquery.min.js", "jQuery.fn.init"),
    "Bootstrap": ("bootstrap.bundle", "data-bs-toggle", "bs.modal"),
    "Leaflet": ("L.TileLayer", "leaflet.css", "_leaflet_id"),
    "OpenLayers": ("ol/Map", "ol.Map", "openlayers"),
    "MapLibre/Mapbox": ("mapbox-gl", "maplibre-gl", "MapboxGeocoder"),
    "ArcGIS API for JS": ("esri/Map", "arcgis.com", "esri/layers"),
    "Cesium": ("Cesium.Viewer", "cesiumWidgets"),
    "D3": ("d3.select", "d3-selection"),
    "Chart.js": ("Chart.register", "chart.js"),
    "Axios": ("axios/lib", "AxiosError"),
    "SignalR": ("HubConnectionBuilder", "signalr"),
    "Sentry": ("@sentry/browser", "sentry-trace"),
    "SheetJS/xlsx": ("SheetJS", "sheetjs", "XLSX.utils"),
    "Google Analytics": ("google-analytics.com", "gtag(", "GoogleAnalyticsObject"),
    "Yandex Metrica": ("mc.yandex", "ym(", "yaCounter"),
}


def detect_from_source(text: str, limit: int = 2_000_000) -> set[str]:
    """Fingerprint frameworks from the body of a downloaded script.

    Hashed bundle names (``main-es2015.9df497eb.js``) carry no brand, so a build
    output can only be identified by what is inside it.

    Args:
        text: Script body.
        limit: Maximum number of characters to scan, keeping large bundles cheap.

    Returns:
        The set of detected technology names.
    """
    haystack = text[:limit]
    return {
        name
        for name, needles in SOURCE_SIGNATURES.items()
        if any(needle in haystack for needle in needles)
    }


def detect_technologies(page: PageData, headers: dict[str, str] | None = None) -> list[str]:
    """Fingerprint frameworks and servers from markup and headers.

    Args:
        page: Parsed page data.
        headers: Response headers of the page.

    Returns:
        A sorted list of detected technology names.
    """
    found: set[str] = set()
    haystack = " ".join(
        [
            " ".join(page.scripts),
            " ".join(page.links),
            " ".join(page.generators),
            " ".join(page.inline_scripts)[:20000],
        ]
    ).lower()

    signatures = {
        "Next.js": ("/_next/", "__next_data__"),
        "Nuxt": ("/_nuxt/", "__nuxt__"),
        "React": ("react-dom", "react.production"),
        "Vue": ("vue.runtime", "vue.min.js", "__vue__"),
        "Angular": ("ng-version", "angular.min.js", "@angular"),
        "Svelte": ("svelte", "__svelte"),
        "jQuery": ("jquery",),
        "WordPress": ("/wp-content/", "/wp-includes/", "wp-json", "wordpress"),
        "Drupal": ("/sites/default/files", "drupal.settings"),
        "Django": ("csrfmiddlewaretoken",),
        "Laravel": ("laravel_session", "/livewire/"),
        "ArcGIS API for JS": ("arcgis", "esri/"),
        "OpenLayers": ("openlayers", "ol.js", "ol-layer"),
        "Leaflet": ("leaflet",),
        "MapLibre/Mapbox": ("maplibre", "mapbox-gl"),
        "Cesium": ("cesium",),
        "GraphQL client": ("apollo", "urql", "relay-runtime"),
        "Swagger UI": ("swagger-ui",),
    }
    for name, needles in signatures.items():
        if any(needle in haystack for needle in needles):
            found.add(name)

    lowered_headers = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    for header in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        value = lowered_headers.get(header)
        if value:
            found.add(value.strip()[:60])
    return sorted(found)
