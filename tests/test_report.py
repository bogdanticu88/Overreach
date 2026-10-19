from __future__ import annotations

from overreach.breaker import recommend
from overreach.chains import Chain, Evidence, Outcome, Step
from overreach.report import narrative, to_html, to_sarif


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
    assert run["tool"]["driver"]["name"] == "overreach"
    assert len(run["results"]) == 2
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert "overreach/data_theft" in rule_ids


def test_sarif_levels_and_fingerprints():
    doc = to_sarif([_chain(Outcome.DATA_THEFT, 5)])
    res = doc["runs"][0]["results"][0]
    assert res["level"] == "error"            # impact 5
    assert res["partialFingerprints"]["overreachChainId"]
    assert res["properties"]["evidence"] == "hypothetical"


def test_narrative_is_short():
    text = narrative(_chain(Outcome.TAKEOVER, 5))
    assert "take over the account" in text
    assert text.count(".") <= 6


def test_html_is_self_contained():
    chains = [_chain(Outcome.DATA_THEFT, 5)]
    html = to_html(chains, recommend(chains), "Demo API")
    assert html.startswith("<!doctype html>")
    assert "Demo API" in html
    assert "data theft" in html
    # No external assets.
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html


def test_html_escapes_content():
    steps = (Step("GET /a<script>", "x"), Step("POST /b", "y"))
    ch = Chain(steps=steps, source_op="GET /a<script>", source_field="body",
               outcome=Outcome.DATA_THEFT, boundaries=("b",), impact=5,
               plausibility=0.7, min_confidence=0.6)
    html = to_html([ch], [], "T")
    assert "<script>" not in html.replace("<script", "")  # the literal is escaped
    assert "&lt;script&gt;" in html
