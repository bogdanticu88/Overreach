from __future__ import annotations

from overreach.breaker import recommend
from overreach.chains import Chain, Evidence, Outcome, Step


def _chain(ops, source_field, outcome, impact):
    steps = tuple(Step(o, "") for o in ops)
    return Chain(steps=steps, source_op=ops[0], source_field=source_field,
                 outcome=outcome, boundaries=("b",), impact=impact,
                 plausibility=0.8, min_confidence=0.7,
                 evidence=Evidence.HYPOTHETICAL)


def test_recommend_covers_all_chains():
    chains = [
        _chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5),
        _chain(["GET /a", "PATCH /user/email"], "body", Outcome.TAKEOVER, 5),
    ]
    options = recommend(chains)
    assert options
    # The top option should break every chain (marking 'body' untrusted hits both).
    assert options[0].chains_broken == 2


def test_workflow_hits_penalise_disruptive_controls():
    chains = [_chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5)]
    # A workflow that legitimately uses the terminal operation.
    options = recommend(chains, workflows=[["POST /hooks"]])
    # At least one option breaks the chain without touching the workflow op
    # (marking the field untrusted hits no workflow).
    assert any(o.chains_broken == 1 and o.workflow_hits == 0 for o in options)


def test_no_chains_no_options():
    assert recommend([]) == []
