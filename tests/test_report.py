from __future__ import annotations

from apd.chains import Chain, Evidence, Outcome, Step
from apd.report import narrative, to_sarif


def _chain(outcome, impact, generic=False):
    steps = (Step("GET /a", "reads untrusted"), Step("POST /b", "acts"))
    return Chain(steps=steps, source_op="GET /a", source_field="body",
                 outcome=outcome, boundaries=("b",), impact=impact,
                 plausibility=0.7, min_confidence=0.6,
                 evidence=Evidence.HYPOTHETICAL, generic=generic)


def test_sarif_shape():
    chains = [_chain(Outcome.DATA_THEFT, 5), _chain(Outcome.DESTRUCTION, 4)]
    doc = to_sarif(chains, spec_path="spec.json")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "apd"
    assert len(run["results"]) == 2
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert "apd/data_theft" in rule_ids


def test_sarif_levels_and_fingerprints():
    doc = to_sarif([_chain(Outcome.DATA_THEFT, 5)])
    res = doc["runs"][0]["results"][0]
    assert res["level"] == "error"            # impact 5
    assert res["partialFingerprints"]["apdChainId"]
    assert res["properties"]["evidence"] == "hypothetical"


def test_narrative_is_short():
    text = narrative(_chain(Outcome.TAKEOVER, 5))
    assert "take over the account" in text
    assert text.count(".") <= 6
