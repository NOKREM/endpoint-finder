"""``XMLHttpRequest`` specific extraction, including simple variable resolution."""

from __future__ import annotations

from endpoint_finder.discovery import regex as rules
from endpoint_finder.discovery.classifier import classify, guess_method
from endpoint_finder.models import Confidence, Endpoint, HttpMethod
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import AnalysisContext, resolve_string_variable

#: Shared with the concatenation rule; re-exported for backwards compatibility.
resolve_variable = resolve_string_variable


def extract(text: str, ctx: AnalysisContext) -> list[Endpoint]:
    """Extract endpoints from ``XMLHttpRequest`` call sites.

    Handles both literal targets (``xhr.open("GET", "/api/x")``) and variable
    targets resolved through :func:`resolve_variable`.

    Args:
        text: JavaScript source.
        ctx: Resolution context.

    Returns:
        Endpoints with the observed HTTP verb attached.
    """
    endpoints: list[Endpoint] = []

    for match in rules.XHR_OPEN.finditer(text):
        endpoint = _build(match.group(2), match.group(1), match.group(0), ctx, Confidence.HIGH)
        if endpoint:
            endpoints.append(endpoint)

    for match in rules.XHR_OPEN_VAR.finditer(text):
        variable = match.group(2)
        resolved = resolve_variable(text, variable)
        if not resolved:
            continue
        endpoint = _build(
            resolved,
            match.group(1),
            f"{match.group(0)} -> {variable}={resolved}",
            ctx,
            Confidence.MEDIUM,
        )
        if endpoint:
            endpoint.tags = sorted({*endpoint.tags, f"var:{variable}"})
            endpoints.append(endpoint)
    return endpoints


def _build(
    raw_url: str, verb: str, evidence: str, ctx: AnalysisContext, confidence: Confidence
) -> Endpoint | None:
    """Normalise one XHR target into an endpoint."""
    candidate = urlutil.clean_candidate(raw_url)
    if not candidate or not urlutil.is_probably_url(candidate):
        return None
    resolved = urlutil.absolutize(ctx.source_url, urlutil.strip_template_placeholders(candidate))
    normalised = urlutil.normalize(resolved) if resolved else None
    if not normalised:
        return None
    if not urlutil.matches_filters(normalised, ctx.include or [], ctx.exclude or []):
        return None
    try:
        method = HttpMethod(verb.upper())
    except ValueError:
        method = HttpMethod.GET
    etype = classify(normalised, hint="xhr")
    return Endpoint(
        url=normalised,
        method=guess_method(normalised, etype, method),
        method_observed=True,
        type=etype,
        source=ctx.source_kind,
        source_url=ctx.source_url,
        evidence=evidence,
        confidence=confidence,
        tags=["rule:XMLHttpRequest"],
    )
