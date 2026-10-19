"""Report rendering: JSON for machines, a short narrative for a security lead."""
from __future__ import annotations

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
