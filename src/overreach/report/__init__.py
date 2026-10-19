"""Report rendering: JSON for machines, a short narrative for a security lead,
and SARIF for GitHub code scanning."""
from __future__ import annotations

from typing import Any

from overreach import __version__
from overreach.breaker import Option
from overreach.chains import Chain

_IMPACT_WORD = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low"}


def chain_to_dict(ch: Chain) -> dict[str, object]:
    return {
        "id": ch.chain_id,
        "outcome": ch.outcome.value,
        "evidence": ch.evidence.value,
        "impact": ch.impact,
        "plausibility": ch.plausibility,
        "min_confidence": ch.min_confidence,
        "source": {"operation": ch.source_op, "field": ch.source_field},
        "boundaries": list(ch.boundaries),
        "steps": [{"op": s.op_key, "note": s.note} for s in ch.steps],
    }


def option_to_dict(opt: Option) -> dict[str, object]:
    return {
        "chains_broken": opt.chains_broken,
        "chains_total": opt.chains_total,
        "workflow_hits": opt.workflow_hits,
        "total_effort": opt.total_effort,
        "controls": [{"kind": c.kind.value, "target": c.target,
                      "effort": c.effort, "description": c.description}
                     for c in opt.controls],
    }


def _level(impact: int) -> str:
    return "error" if impact >= 5 else "warning" if impact == 4 else "note"


def to_sarif(chains: list[Chain], spec_path: str = "openapi.json") -> dict[str, Any]:
    """Render findings as SARIF 2.1.0 for GitHub code scanning.

    Each outcome is a rule; each chain is a result, anchored to its terminal
    operation as a logical location and fingerprinted by chain id so the same
    chain is tracked across runs.
    """
    outcomes = sorted({c.outcome.value for c in chains})
    rules = [{
        "id": f"overreach/{o}",
        "name": o,
        "shortDescription": {"text": f"Agent attack chain: {o.replace('_', ' ')}"},
        "defaultConfiguration": {"level": "error"},
    } for o in outcomes]

    results = []
    for c in chains:
        results.append({
            "ruleId": f"overreach/{c.outcome.value}",
            "level": _level(c.impact),
            "message": {"text": narrative(c)},
            "locations": [{
                "logicalLocations": [{
                    "fullyQualifiedName": c.steps[-1].op_key,
                    "kind": "function",
                }],
                "physicalLocation": {
                    "artifactLocation": {"uri": spec_path},
                },
            }],
            "partialFingerprints": {"overreachChainId": c.chain_id},
            "properties": {
                "evidence": c.evidence.value,
                "impact": c.impact,
                "plausibility": c.plausibility,
                "generic": c.generic,
                "boundaries": list(c.boundaries),
                "path": [s.op_key for s in c.steps],
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "overreach",
                "informationUri": "https://github.com/bogdanticu88/overreach",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def to_html(chains: list[Chain], options: list[Option], title: str) -> str:
    """A self-contained HTML report for a security lead. No external assets."""
    badge = {"error": "#b4232a", "warning": "#b5790f", "note": "#5a6472"}
    rows = []
    for i, c in enumerate(chains, 1):
        lvl = _level(c.impact)
        steps = " &rarr; ".join(_esc(s.op_key) for s in c.steps)
        bnds = "".join(f"<li>{_esc(b)}</li>" for b in c.boundaries)
        rows.append(f"""
        <div class="finding">
          <div class="head">
            <span class="num">#{i}</span>
            <span class="pill" style="background:{badge[lvl]}">{c.outcome.value.replace('_',' ')}</span>
            <span class="tag">{'generic' if c.generic else 'specific'}</span>
            <span class="ev">evidence: {c.evidence.value}</span>
            <span class="id">{c.chain_id}</span>
          </div>
          <p class="narr">{_esc(narrative(c))}</p>
          <div class="path">{steps}</div>
          <ul class="bnds">{bnds}</ul>
        </div>""")

    fixes = []
    for j, o in enumerate(options, 1):
        ctls = "".join(f"<li>{_esc(c.description)} "
                       f"<span class='eff'>effort {c.effort}</span></li>"
                       for c in o.controls)
        fixes.append(f"""
        <div class="opt">
          <div class="opthead">Option {j}: breaks {o.chains_broken}/{o.chains_total}
            chains &middot; {o.workflow_hits} workflow hit(s) &middot; effort {o.total_effort}</div>
          <ul>{ctls}</ul>
        </div>""")

    spec_n = len([c for c in chains if not c.generic])
    gen_n = len(chains) - spec_n
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent attack paths: {_esc(title)}</title>
<style>
  :root {{ color-scheme: light dark; --bg:#fff; --fg:#1a1d21; --muted:#5a6472;
    --card:#f6f7f9; --line:#e2e5ea; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171a; --fg:#e8eaed;
    --muted:#9aa4b2; --card:#1c2024; --line:#2a2f35; }} }}
  body {{ background:var(--bg); color:var(--fg); margin:0;
    font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); margin:0 0 24px; }}
  .finding {{ background:var(--card); border:1px solid var(--line);
    border-radius:10px; padding:16px; margin:12px 0; }}
  .head {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap;
    font-size:13px; }}
  .num {{ font-weight:700; }}
  .pill {{ color:#fff; padding:2px 9px; border-radius:20px; font-weight:600; }}
  .tag,.ev,.id {{ color:var(--muted); }}
  .id {{ margin-left:auto; font-family:ui-monospace,monospace; }}
  .narr {{ margin:10px 0 8px; }}
  .path {{ font-family:ui-monospace,monospace; font-size:13px;
    background:var(--bg); border:1px solid var(--line); border-radius:6px;
    padding:8px 10px; overflow-x:auto; }}
  .bnds {{ margin:8px 0 0; padding-left:18px; color:var(--muted); font-size:13px; }}
  h2 {{ font-size:17px; margin:32px 0 8px; }}
  .opt {{ background:var(--card); border:1px solid var(--line);
    border-radius:10px; padding:12px 16px; margin:10px 0; }}
  .opthead {{ font-weight:600; margin-bottom:6px; }}
  .eff {{ color:var(--muted); font-size:12px; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:32px; }}
</style></head>
<body><div class="wrap">
  <h1>Agent attack paths: {_esc(title)}</h1>
  <p class="sub">{len(chains)} finding(s) &middot; {spec_n} specific, {gen_n} generic.
    Evidence is from the spec (hypothetical) unless a finding says otherwise.</p>
  {''.join(rows) if rows else '<p>No chains found.</p>'}
  <h2>Ranked fixes</h2>
  {''.join(fixes) if fixes else '<p>No fixes needed.</p>'}
  <footer>Generated by overreach {__version__}. Findings are reachability analysis of the
    API specification, not proof that the running system is exploitable.</footer>
</div></body></html>"""


def narrative(ch: Chain) -> str:
    verb = {"data_theft": "exfiltrate data", "takeover": "take over the account",
            "destruction": "destroy data", "fraud": "commit fraud",
            "cost": "run up cost"}.get(ch.outcome.value, ch.outcome.value)
    first = ch.steps[0].op_key
    last = ch.steps[-1].op_key
    lead = (f"An attacker writes text into {ch.source_field or 'a field'} that the "
            f"agent later reads at {first}.")
    body = (f"Following that text, the agent can {verb} by reaching {last} "
            f"in {ch.length} step(s), each individually permitted.")
    cross = f"Boundary crossed: {ch.boundaries[0]}." if ch.boundaries else ""
    grade = (f"Evidence: {ch.evidence.value}; impact {_IMPACT_WORD[ch.impact]}; "
             f"plausibility {ch.plausibility:.2f}.")
    return " ".join(x for x in (lead, body, cross, grade) if x)
