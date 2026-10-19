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


def test_cross_tenant_read_detected_under_tenant_boundary():
    api = _api()
    b = load_text(REF_BND.read_text())
    assert b.agent_tenant == "acme"
    chains = find_chains(api, boundaries=b)
    ct = [c for c in chains
          if c.steps[-1].op_key == "GET /repos/{owner}/{repo}/contents/{path}"]
    assert ct, "a tenant-scoped read should be flagged as cross-tenant data theft"
    assert any("tenant boundary" in bnd for bnd in ct[0].boundaries)


def test_cross_tenant_read_validates():
    from fastapi.testclient import TestClient

    from apd.reference_api import app as refapp
    from apd.reference_api import reset_state
    from apd.replay import validate_cross_tenant_read
    reset_state()
    res = validate_cross_tenant_read(TestClient(refapp))
    assert res.evidence.value == "validated"
    assert "ownership" in res.detail


def test_no_tenant_boundary_no_cross_tenant_finding():
    # Without agent_tenant, a plain read is not promoted to a terminal.
    api = _api()
    b = Boundaries(allowed_ops=("GET /repos/{owner}/{repo}/contents/{path}",),
                   tenant_param="owner")  # no agent_tenant
    chains = find_chains(api, boundaries=b)
    assert not any(c.steps[-1].op_key == "GET /repos/{owner}/{repo}/contents/{path}"
                   for c in chains)
