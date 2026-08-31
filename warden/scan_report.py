"""Render a `warden scan` result as a self-contained, shareable HTML finding."""

from __future__ import annotations

import html
import json

_CSS = """
:root{--bg:#0e1013;--panel:#16191e;--ink:#e8eaed;--muted:#9aa1ac;--line:#262b33;
--accent:#7d95ff;--ok:#35c66b;--bad:#ff6b6b;--warn:#f0a83c;--chip:#1e232b}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--panel:#fff;--ink:#1a1d21;
--muted:#6b7280;--line:#e5e7eb;--accent:#5d7cff;--ok:#16a34a;--bad:#dc2626;
--warn:#d97706;--chip:#eef1f5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:40px 22px 80px}
h1{font-size:30px;letter-spacing:-.5px;margin:.2em 0}
h2{font-size:17px;margin:34px 0 12px}.sub{color:var(--muted);margin-top:0}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:24px 0}
@media(max-width:640px){.stats{grid-template-columns:1fr 1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.stat .n{font-size:32px;font-weight:800;letter-spacing:-1px}
.stat .n.bad{color:var(--bad)}.stat .n.warn{color:var(--warn)}
.stat .l{color:var(--muted);font-size:12.5px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;
border-bottom:1px solid var(--line);font-size:13.5px}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
.pill.crit{background:var(--bad);color:#fff}.pill.high{background:rgba(255,107,107,.15);color:var(--bad)}
.pill.med{background:rgba(240,168,60,.15);color:var(--warn)}.pill.low{background:var(--chip);color:var(--muted)}
.tag{display:inline-block;background:var(--chip);color:var(--muted);border-radius:6px;
padding:1px 7px;margin:1px;font-size:11px}.tag.bad{color:var(--bad)}
.foot{color:var(--muted);font-size:12.5px;margin-top:40px;border-top:1px solid var(--line);padding-top:16px}
.bar{height:8px;background:var(--chip);border-radius:99px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;background:var(--bad)}
"""


def _stat(n, label, kind=""):
    return (f'<div class="card stat"><div class="n {kind}">{html.escape(str(n))}</div>'
            f'<div class="l">{html.escape(label)}</div></div>')


def _lvl(level):
    return {"critical": "crit", "high": "high", "medium": "med"}.get(level, "low")


def render_html(agg: dict, title: str = "AI Agent Skill Behavior Scan") -> str:
    t = html.escape(title)
    stats = "".join([
        _stat(agg["total"], "skills scanned"),
        _stat(f'{agg["pct_contacting_undisclosed"]}%', "contacted an undisclosed host",
              "bad" if agg["pct_contacting_undisclosed"] else ""),
        _stat(f'{agg["pct_contacting_suspicious"]}%', "reached suspicious infrastructure",
              "bad" if agg["pct_contacting_suspicious"] else ""),
        _stat(f'{agg["pct_credential_refs"]}%', "reference credential paths",
              "warn" if agg["pct_credential_refs"] else ""),
        _stat(f'{agg["pct_injection_patterns"]}%', "contain injection patterns",
              "warn" if agg["pct_injection_patterns"] else ""),
        _stat(agg["detonated"], "dynamically inspected"),
    ])

    def host_rows(pairs):
        if not pairs:
            return '<tr><td class="muted">none</td><td></td></tr>'
        mx = pairs[0][1] if pairs else 1
        return "".join(
            f'<tr><td class="mono">{html.escape(h)}</td>'
            f'<td>{n}<div class="bar"><i style="width:{round(100*n/mx)}%"></i></div></td></tr>'
            for h, n in pairs)

    def _tags(items, cls):
        if not items:
            return '<span class="muted">—</span>'
        return "".join('<span class="' + cls + '">' + html.escape(x) + '</span>' for x in items)

    def _offender_row(o):
        return (
            "<tr><td>" + html.escape(o["name"]) + "</td>"
            + '<td><span class="pill ' + _lvl(o["level"]) + '">'
            + str(o["risk"]) + " " + html.escape(o["level"]) + "</span></td>"
            + "<td>" + _tags(o["undisclosed"][:5], "tag") + "</td>"
            + "<td>" + _tags((o["suspicious"] + o["injection"])[:4], "tag bad") + "</td></tr>")

    offenders = "".join(_offender_row(o) for o in agg["worst_offenders"]) \
        or '<tr><td class="muted">no notable offenders</td><td></td><td></td><td></td></tr>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{t}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>{t}</h1>
<p class="sub">Each skill was analyzed statically and, where runnable,
<b>time-boxed under strict host confinement</b> with egress blocked by default
and recorded. This dynamic mode is for semi-trusted code; use the disposable
container harness for unknown code. Percentages are of {agg['total']} skills.</p>
<div class="stats">{stats}</div>

<h2>Where they connected — undisclosed hosts</h2>
<div class="card"><table><thead><tr><th>Host not declared by the skill</th><th>skills</th></tr></thead>
<tbody>{host_rows(agg['top_undisclosed'])}</tbody></table></div>

<h2>Suspicious infrastructure reached</h2>
<div class="card"><table><thead><tr><th>Exfil / callback / raw-IP host</th><th>skills</th></tr></thead>
<tbody>{host_rows(agg['top_suspicious'])}</tbody></table></div>

<h2>Highest-risk skills</h2>
<div class="card"><table><thead><tr><th>Skill</th><th>Risk</th><th>Undisclosed hosts</th><th>Flags</th></tr></thead>
<tbody>{offenders}</tbody></table></div>

<div class="foot">Generated by <b>Warden</b> — least privilege and a flight
recorder for AI coding agents. Static + dynamic behavioral analysis, local-first,
no telemetry. Method: {agg['detonated']} of {agg['total']} skills were executed
under host confinement; the rest were analyzed statically only.</div>
</div></body></html>"""


def render_json(agg: dict, results: list[dict]) -> str:
    return json.dumps({"summary": agg, "results": results}, indent=2)
