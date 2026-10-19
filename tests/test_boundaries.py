from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from apd.boundaries import Boundaries, load_text
from apd.chains import find_chains
from apd.infer import infer_api
from apd.ingest import load_text as load_spec
from apd.reference_api import app

REF_BND = Path(__file__).parent.parent / "src" / "apd" / "reference_api" / "boundaries.yaml"


def _api():
    spec = json.dumps(TestClient(app).get("/openapi.json").json())
    return infer_api(load_spec(spec))


def test_loader_reads_scope_and_tenant():
    b = load_text(REF_BND.read_text())
    assert b.acts_as == "support-agent"
    assert b.allowed_ops is not None
    assert b.tenant_param == "owner"
    assert b.allows("POST /repos/{owner}/{repo}/hooks")
    assert not b.allows("PATCH /user/email")


def test_scope_filters_out_unreachable_terminal():
    api = _api()
    b = load_text(REF_BND.read_text())
    scoped = find_chains(api, boundaries=b)
    keys = {c.steps[-1].op_key for c in scoped}
    # The email-change terminal is outside the agent's scope, so it drops out.
    assert "PATCH /user/email" not in keys
    # The exfiltration chain is within scope and remains.
    assert any(c.outcome.value == "data_theft"
               and c.steps[-1].op_key == "POST /repos/{owner}/{repo}/hooks"
               for c in scoped)


def test_scoped_findings_are_not_generic():
    api = _api()
    b = load_text(REF_BND.read_text())
    scoped = find_chains(api, boundaries=b)
    assert scoped and all(not c.generic for c in scoped)
    # Boundary labels mention the acting principal.
    assert any("support-agent" in " ".join(c.boundaries) for c in scoped)


def test_no_boundaries_leaves_reach_generic():
    api = _api()
    chains = find_chains(api)
    assert any(c.generic for c in chains)


def test_unknown_scope_allows_everything():
    b = Boundaries()  # no allowed_ops
    assert b.allows("anything at all")
