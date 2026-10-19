"""Report rendering: JSON for machines, a short narrative for a security lead,
and SARIF for GitHub code scanning."""
from __future__ import annotations

from typing import Any

from apd import __version__
from apd.breaker import Option
from apd.chains import Chain

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
        "id": f"apd/{o}",
        "name": o,
        "shortDescription": {"text": f"Agent attack chain: {o.replace('_', ' ')}"},
        "defaultConfiguration": {"level": "error"},
    } for o in outcomes]

    results = []
    for c in chains:
        results.append({
            "ruleId": f"apd/{c.outcome.value}",
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
            "partialFingerprints": {"apdChainId": c.chain_id},
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
                "name": "apd",
                "informationUri": "https://github.com/bogdanticu88/apd",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }


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
