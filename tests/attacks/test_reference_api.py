"""End-to-end: the reference API is linter-clean in shape yet carries chains the
tool finds and the harness validates."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from overreach.chains import Evidence, Outcome, find_chains
from overreach.ingest import load_text
from overreach.infer import infer_api
from overreach.replay import validate_exfiltration, validate_takeover
from overreach.reference_api import app, reset_state


def _api():
    client = TestClient(app)
    spec = json.dumps(client.get("/openapi.json").json())
    return infer_api(load_text(spec))


def test_spec_parses_with_operations():
    api = _api()
    assert len(api.operations) >= 7
    # The sink endpoint must not appear in the public spec.
    assert not any("_sink" in op.path for op in api.operations)


def test_finds_exfiltration_chain():
    chains = find_chains(_api())
    assert any(c.outcome == Outcome.DATA_THEFT
               and any("hooks" in s.op_key for s in c.steps) for c in chains)


def test_finds_takeover_chain():
    chains = find_chains(_api())
    assert any(c.outcome == Outcome.TAKEOVER for c in chains)


def test_exfiltration_validates_with_canary():
    reset_state()
    client = TestClient(app)
    res = validate_exfiltration(client)
    assert res.evidence == Evidence.VALIDATED
    assert "webhook" in res.detail


def test_takeover_validates_with_canary():
    reset_state()
    client = TestClient(app)
    res = validate_takeover(client)
    assert res.evidence == Evidence.VALIDATED


def test_all_chains_start_hypothetical():
    chains = find_chains(_api())
    assert chains and all(c.evidence == Evidence.HYPOTHETICAL for c in chains)
