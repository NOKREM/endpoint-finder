"""Self-contained, filterable HTML report."""

from __future__ import annotations

import html
from pathlib import Path

import orjson

from endpoint_finder.discovery import api as apimod
from endpoint_finder.models import ScanResult

_TEMPLATE = """<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>endpoint-finder &middot; {title}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #16181d; --muted: #626a75; --line: #e3e6ea;
  --card: #f7f8fa; --accent: #2a6df4; --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg: #101317; --fg: #e7eaee; --muted: #98a1ad; --line: #262b32;
           --card: #171b21; --accent: #6ea1ff; }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
.wrap {{ max-width: 1240px; margin: 0 auto; padding: 32px 20px 64px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }}
h2 {{ font-size: 15px; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }}
a {{ color: var(--accent); text-decoration: none; overflow-wrap: anywhere; }}
a:hover {{ text-decoration: underline; }}
.sub {{ color: var(--muted); font-size: 13px; margin-bottom: 24px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }}
.card {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }}
.card .n {{ font-size: 24px; font-weight: 650; font-variant-numeric: tabular-nums; }}
.card .l {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}
.controls {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 20px 0 12px; }}
input[type=search], select {{ background: var(--card); color: var(--fg); border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 11px; font: inherit; font-size: 14px; }}
input[type=search] {{ flex: 1 1 260px; }}
.tablewrap {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13.5px; }}
th, td {{ text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ position: sticky; top: 0; background: var(--card); font-size: 11.5px; text-transform: uppercase;
     letter-spacing: .06em; color: var(--muted); cursor: pointer; white-space: nowrap; }}
tbody tr:last-child td {{ border-bottom: none; }}
tbody tr:hover {{ background: var(--card); }}
code {{ font-family: var(--mono); font-size: 12.5px; }}
.tag {{ display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px;
        border: 1px solid var(--line); background: var(--card); color: var(--muted); white-space: nowrap; }}
.m {{ font-family: var(--mono); font-size: 11.5px; font-weight: 600; }}
.m-GET {{ color: #2f9e57; }} .m-POST {{ color: #d98324; }} .m-PUT {{ color: #9a6fd8; }}
.m-DELETE {{ color: #d64545; }} .m-PATCH {{ color: #c9a227; }} .m-ANY {{ color: var(--muted); }}
.ev {{ color: var(--muted); font-family: var(--mono); font-size: 11.5px; display: block;
       max-width: 460px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.err td {{ color: var(--muted); font-size: 12.5px; }}
footer {{ margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 16px; }}
.empty {{ padding: 28px; text-align: center; color: var(--muted); }}
.note {{ color: var(--muted); font-size: 13px; margin: 0 0 10px; }}
ul.routes {{ list-style: none; padding: 0; margin: 0; display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 6px; }}
ul.routes li {{ background: var(--card); border: 1px solid var(--line);
  border-radius: 8px; padding: 7px 11px; overflow: hidden; text-overflow: ellipsis; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{title}</h1>
  <div class="sub">
    <a href="{target}" rel="noreferrer noopener">{target}</a> &middot;
    scanned {scan_time} &middot; {duration}s &middot; passive discovery
  </div>

  <div class="cards">{cards}</div>

  <h2>Endpoints</h2>
  <div class="controls">
    <input type="search" id="q" placeholder="Filter by URL, tag, evidence or source&hellip;" autocomplete="off">
    <select id="type"><option value="">All types</option>{type_options}</select>
    <select id="method"><option value="">All methods</option>{method_options}</select>
    <select id="conf">
      <option value="">Any confidence</option>
      <option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
    </select>
  </div>
  <div class="tablewrap">
    <table id="tbl">
      <thead><tr>
        <th data-k="type">Type</th><th data-k="method">Method</th><th data-k="url">URL</th>
        <th data-k="source">Source</th><th data-k="confidence">Conf.</th><th data-k="status_code">Status</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <div class="empty" id="empty" hidden>No endpoint matches the current filters.</div>

  {technologies}
  {routes}
  {errors}

  <footer>Generated by endpoint-finder &middot; {total} endpoints from {sources} distinct sources.</footer>
</div>
<script id="data" type="application/json">{payload}</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const rows = document.getElementById('rows');
const empty = document.getElementById('empty');
const q = document.getElementById('q');
const fType = document.getElementById('type');
const fMethod = document.getElementById('method');
const fConf = document.getElementById('conf');
let sortKey = null, sortDir = 1;

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
  {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));

function render() {{
  const term = q.value.trim().toLowerCase();
  const t = fType.value, m = fMethod.value, c = fConf.value;
  let list = DATA.filter(e =>
    (!t || e.type === t) && (!m || e.method === m) && (!c || e.confidence === c) &&
    (!term || (e.url + ' ' + e.source + ' ' + (e.source_url||'') + ' ' + (e.evidence||'') + ' ' +
               (e.tags||[]).join(' ') + ' ' + (e.params||[]).join(' ')).toLowerCase().includes(term)));
  if (sortKey) {{
    list = list.slice().sort((a, b) => {{
      const x = a[sortKey] ?? '', y = b[sortKey] ?? '';
      return (x > y ? 1 : x < y ? -1 : 0) * sortDir;
    }});
  }}
  empty.hidden = list.length > 0;
  rows.innerHTML = list.map(e => `<tr>
    <td><span class="tag">${{esc(e.type)}}</span></td>
    <td><span class="m m-${{esc(e.method)}}">${{esc(e.method)}}</span></td>
    <td><a href="${{esc(e.url)}}" rel="noreferrer noopener"><code>${{esc(e.url)}}</code></a>
        ${{e.evidence ? `<span class="ev">${{esc(e.evidence)}}</span>` : ''}}
        ${{(e.params||[]).length ? `<span class="ev">params: ${{esc((e.params||[]).join(', '))}}</span>` : ''}}</td>
    <td><span class="tag">${{esc(e.source)}}</span></td>
    <td>${{esc(e.confidence)}}</td>
    <td>${{e.status_code ?? ''}}</td>
  </tr>`).join('');
}}

document.querySelectorAll('#tbl th').forEach(th => th.addEventListener('click', () => {{
  const k = th.dataset.k;
  sortDir = (sortKey === k) ? -sortDir : 1;
  sortKey = k;
  render();
}}));
[q, fType, fMethod, fConf].forEach(el => el.addEventListener('input', render));
render();
</script>
</body>
</html>
"""


def _cards(result: ScanResult) -> str:
    """Render the summary cards."""
    summary = apimod.summarize(result.endpoints)
    items = [
        ("endpoints", summary["total"]),
        ("routes", summary["routes"]),
        ("hosts", summary["hosts"]),
        ("high conf.", summary["high_confidence"]),
        ("observed live", summary["observed"]),
        ("scripts", result.stats.scripts),
        ("requests", result.stats.requests),
        ("pages", result.stats.pages),
    ]
    return "".join(
        f'<div class="card"><div class="n">{value}</div><div class="l">{html.escape(label)}</div></div>'
        for label, value in items
    )


def _options(values: list[str]) -> str:
    """Render ``<option>`` elements for a filter dropdown."""
    return "".join(f"<option>{html.escape(value)}</option>" for value in values)


def _technologies(result: ScanResult) -> str:
    """Render the detected technology section."""
    if not result.technologies:
        return ""
    tags = " ".join(f'<span class="tag">{html.escape(item)}</span>' for item in result.technologies)
    return f"<h2>Detected technologies</h2><div>{tags}</div>"


def _routes(result: ScanResult) -> str:
    """Render the client side route section."""
    if not result.routes:
        return ""
    items = "".join(
        f'<li><a href="{html.escape(route)}" rel="noreferrer noopener">'
        f"<code>{html.escape(route)}</code></a></li>"
        for route in result.routes
    )
    return (
        f"<h2>Client side routes ({len(result.routes)})</h2>"
        "<p class='note'>Navigable views of the single page application, not request targets. "
        "Each one was rendered so that the requests it fires appear above.</p>"
        f"<ul class='routes'>{items}</ul>"
    )


def _errors(result: ScanResult) -> str:
    """Render the error table."""
    if not result.errors:
        return ""
    rows = "".join(
        f"<tr class='err'><td><span class='tag'>{html.escape(error.category)}</span></td>"
        f"<td><code>{html.escape(error.url)}</code></td><td>{html.escape(error.message)}</td></tr>"
        for error in result.errors[:200]
    )
    return (
        "<h2>Warnings and errors</h2><div class='tablewrap'><table>"
        "<thead><tr><th>Category</th><th>URL</th><th>Detail</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )


def write(result: ScanResult, path: Path) -> Path:
    """Write the interactive HTML report.

    Args:
        result: Completed scan result.
        path: Destination file.

    Returns:
        The path that was written.
    """
    payload = orjson.dumps(
        [
            {
                "url": endpoint.url,
                "method": endpoint.method.value,
                "type": endpoint.type.value,
                "source": endpoint.source.value,
                "source_url": endpoint.source_url,
                "confidence": endpoint.confidence.value,
                "status_code": endpoint.status_code,
                "evidence": endpoint.evidence,
                "params": endpoint.params,
                "tags": endpoint.tags,
            }
            for endpoint in result.endpoints
        ]
    ).decode("utf-8")
    # Prevent the embedded JSON from terminating the script element early.
    payload = payload.replace("</", "<\\/")

    types = sorted({endpoint.type.value for endpoint in result.endpoints})
    methods = sorted({endpoint.method.value for endpoint in result.endpoints})
    sources = len({endpoint.source_url for endpoint in result.endpoints if endpoint.source_url})

    document = _TEMPLATE.format(
        title=html.escape(result.page_title or result.target),
        target=html.escape(result.target),
        scan_time=result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=result.stats.duration_seconds,
        cards=_cards(result),
        type_options=_options(types),
        method_options=_options(methods),
        technologies=_technologies(result),
        routes=_routes(result),
        errors=_errors(result),
        total=len(result.endpoints),
        sources=sources,
        payload=payload,
    )
    path.write_text(document, encoding="utf-8")
    return path
