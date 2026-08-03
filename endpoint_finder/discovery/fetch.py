"""Fetch API specific extraction, including template literal reconstruction."""

from __future__ import annotations

import re

from endpoint_finder.discovery import regex as rules
from endpoint_finder.discovery.classifier import classify, guess_method
from endpoint_finder.models import Confidence, Endpoint, HttpMethod
from endpoint_finder.parser import urls as urlutil
from endpoint_finder.parser.jsparser import AnalysisContext

#: ``fetch(`${base}/api/x`)`` — template literals are the dominant modern pattern.
FETCH_TEMPLATE = re.compile(r"fetch\s*\(\s*`([^`]{2,512})`")
TEMPLATE_ANY = re.compile(r"`((?:[^`\\$]|\$(?!\{)|\\.){0,200}\$\{[^`]{0,400})`")


def extract(text: str, ctx: AnalysisContext, bases: list[str] | None = None) -> list[Endpoint]:
    """Extract endpoints from ``fetch()`` call sites.

    Args:
        text: JavaScript source.
        ctx: Resolution context.
        bases: Additional base URLs used to resolve template literals whose host
            part comes from a configuration constant.

    Returns:
        Endpoints for every resolvable fetch target.
    """
    endpoints: list[Endpoint] = []
    candidate_bases = [ctx.source_url, *(bases or [])]

    for match in rules.FETCH_WITH_METHOD.finditer(text):
        verb = rules.METHOD_IN_OPTIONS.search(match.group("opts") or "")
        endpoints.extend(
            _build(
                match.group(1),
                verb.group(1) if verb else None,
                match.group(0),
                ctx,
                candidate_bases,
            )
        )
    for match in rules.FETCH_CALL.finditer(text):
        endpoints.extend(_build(match.group(1), None, match.group(0), ctx, candidate_bases))
    for match in FETCH_TEMPLATE.finditer(text):
        endpoints.extend(_build(match.group(1), None, match.group(0), ctx, candidate_bases))
    return endpoints


def _build(
    raw_url: str, verb: str | None, evidence: str, ctx: AnalysisContext, bases: list[str]
) -> list[Endpoint]:
    """Resolve one fetch target against every plausible base URL.

    Args:
        raw_url: The literal captured at the call site.
        verb: Verb from the options object, or ``None`` when none was given.
        evidence: Source snippet backing the match.
        ctx: Resolution context.
        bases: Base URLs to resolve bare paths against.

    Returns:
        One endpoint per distinct resolution.
    """
    candidate = urlutil.clean_candidate(raw_url)
    if not candidate:
        return []
    candidate = urlutil.strip_template_placeholders(candidate)
    if not urlutil.is_probably_url(candidate):
        return []
    method: HttpMethod | None = None
    if verb:
        try:
            method = HttpMethod(verb.upper())
        except ValueError:
            method = None

    results: list[Endpoint] = []
    seen: set[str] = set()
    targets = bases if candidate.startswith("/") else bases[:1]
    for base in targets:
        resolved = urlutil.absolutize(base, candidate)
        normalised = urlutil.normalize(resolved) if resolved else None
        if not normalised or normalised in seen:
            continue
        if not urlutil.matches_filters(normalised, ctx.include or [], ctx.exclude or []):
            continue
        seen.add(normalised)
        etype = classify(normalised, hint="fetch")
        results.append(
            Endpoint(
                url=normalised,
                method=guess_method(normalised, etype, method),
                method_observed=method is not None,
                type=etype,
                source=ctx.source_kind,
                source_url=ctx.source_url,
                evidence=evidence,
                confidence=Confidence.HIGH,
                tags=["rule:fetch"],
            )
        )
    return results
