"""Replay evidence must be bound to the chain's exact operation sequence, never
to a loose name match."""
from __future__ import annotations

from fastapi.testclient import TestClient

from overreach.chains import Chain, Evidence, Outcome, Step
from overreach.reference_api import app
from overreach.replay import validate_chain

ENTRY = "GET /repos/{owner}/{repo}/issues/{issue_number}/comments"
HOOKS = "POST /repos/{owner}/{repo}/hooks"


def _chain(op_keys, outcome=Outcome.DATA_THEFT):
    steps = tuple(Step(k, "") for k in op_keys)
    return Chain(steps=steps, source_op=op_keys[0], source_field="body",
                 outcome=outcome, boundaries=("b",), impact=5,
                 plausibility=0.6, min_confidence=0.6)


def test_exact_sequence_validates_and_records():
    ch = _chain((ENTRY, HOOKS))
    res = validate_chain(ch, TestClient(app))
    assert res.evidence == Evidence.VALIDATED
    assert res.chain_id == ch.chain_id
    assert res.record is not None
    assert res.record.ops == (ENTRY, HOOKS)
    assert res.record.leaked


def test_unrelated_sequence_is_not_validated_by_name_match():
    # A chain that merely contains a "hooks" operation but is NOT the known
    # exfiltration sequence must not borrow the exfiltration scenario's result.
    ch = _chain(("GET /admin/hooks", "DELETE /admin/hooks/{id}"))
    res = validate_chain(ch, TestClient(app))
    assert res.evidence == Evidence.HYPOTHETICAL
    assert res.record is None
    assert "no replay scenario" in res.detail


def test_partial_prefix_is_not_matched():
    # Only the entry op, not the full known sequence: no exact match.
    ch = _chain((ENTRY,))
    res = validate_chain(ch, TestClient(app))
    assert res.evidence == Evidence.HYPOTHETICAL
    assert res.record is None


def test_each_run_uses_a_unique_canary():
    ch = _chain((ENTRY, HOOKS))
    a = validate_chain(ch, TestClient(app))
    b = validate_chain(ch, TestClient(app))
    assert a.canary and b.canary and a.canary != b.canary
