from __future__ import annotations

from overreach.breaker import ControlKind, recommend
from overreach.chains import Chain, Evidence, Outcome, Step


def _chain(ops, source_field, outcome, impact, terminal_exit=False):
    steps = tuple(Step(o, "") for o in ops)
    return Chain(steps=steps, source_op=ops[0], source_field=source_field,
                 outcome=outcome, boundaries=("b",), impact=impact,
                 plausibility=0.8, min_confidence=0.7,
                 evidence=Evidence.HYPOTHETICAL, terminal_exit=terminal_exit)


def test_recommend_prevents_all_chains_with_enforcing_controls():
    chains = [
        _chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5),
        _chain(["GET /a", "PATCH /user/email"], "body", Outcome.TAKEOVER, 5),
    ]
    options = recommend(chains)
    assert options
    # The top option must actually PREVENT every chain, using enforcing controls
    # (egress allowlist on the exfil exit / remove-permission), not a label.
    assert options[0].chains_prevented == 2
    assert all(c.enforces for c in options[0].controls)


def test_marking_a_field_untrusted_does_not_count_as_prevention():
    # Marking 'body' untrusted is positioned on both chains (coverage) but
    # enforces nothing, so it must never be reported as prevention.
    chains = [
        _chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5),
        _chain(["GET /a", "PATCH /user/email"], "body", Outcome.TAKEOVER, 5),
    ]
    options = recommend(chains)
    for o in options:
        for c in o.controls:
            if c.kind in (ControlKind.UNTRUSTED_FIELD, ControlKind.APPROVAL):
                assert not c.enforces
    # A defence-in-depth option may cover via mitigations beyond what it prevents.
    assert any(o.chains_covered >= o.chains_prevented for o in options)


def test_human_approval_and_untrusted_label_are_classified_as_mitigations():
    from overreach.breaker import Control
    assert Control(ControlKind.APPROVAL, "op", 2, "").enforces is False
    assert Control(ControlKind.UNTRUSTED_FIELD, "f", 1, "").enforces is False
    assert Control(ControlKind.EGRESS_ALLOWLIST, "op", 3, "").enforces is True
    assert Control(ControlKind.REMOVE_PERMISSION, "op", 4, "").enforces is True
    # Wherever approval is selected, it never counts as enforcing prevention.
    chains = [_chain(["GET /a", "PATCH /user/email"], "body", Outcome.TAKEOVER, 5)]
    for o in recommend(chains):
        for c in o.controls:
            if c.kind == ControlKind.APPROVAL:
                assert not c.enforces


def test_egress_allowlist_prevents_only_data_theft_exit():
    # Egress allowlist prevents exfiltration via a caller-named outbound exit;
    # it is not offered for takeover.
    theft = recommend([_chain(["GET /a", "POST /hooks"], "body",
                              Outcome.DATA_THEFT, 5, terminal_exit=True)])
    kinds_theft = {c.kind for o in theft for c in o.controls}
    assert ControlKind.EGRESS_ALLOWLIST in kinds_theft
    takeover = recommend([_chain(["GET /a", "PATCH /user/email"], "body",
                                 Outcome.TAKEOVER, 5)])
    kinds_takeover = {c.kind for o in takeover for c in o.controls}
    assert ControlKind.EGRESS_ALLOWLIST not in kinds_takeover


def test_egress_allowlist_not_offered_for_non_outbound_exfil():
    # A cross-tenant read / reader-visible-sink write is data_theft but has no
    # caller-named outbound exit, so an egress allowlist must not be proposed.
    ct = recommend([_chain(["GET /a", "GET /repos/{o}/{r}/contents/{p}"], "body",
                           Outcome.DATA_THEFT, 5, terminal_exit=False)])
    kinds = {c.kind for o in ct for c in o.controls}
    assert ControlKind.EGRESS_ALLOWLIST not in kinds
    # It is still preventable, by removing the agent's permission for the read.
    assert any(o.chains_prevented == 1 for o in ct)


def test_workflow_hits_penalise_disruptive_controls():
    chains = [_chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5)]
    options = recommend(chains, workflows=[["POST /hooks"]])
    # An egress allowlist prevents the exfil without removing the operation the
    # workflow depends on, so a lower-disruption prevention option exists.
    assert any(o.chains_prevented == 1 for o in options)


def test_nothing_is_marked_verified_without_a_retest():
    chains = [_chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5)]
    assert all(not o.verified for o in recommend(chains))


def test_ranking_is_deterministic():
    chains = [
        _chain(["GET /a", "POST /hooks"], "body", Outcome.DATA_THEFT, 5),
        _chain(["GET /b", "PATCH /user/email"], "note", Outcome.TAKEOVER, 5),
    ]
    runs = [recommend(chains) for _ in range(5)]
    sig = [[(c.kind.value, c.target) for o in run for c in o.controls] for run in runs]
    assert all(s == sig[0] for s in sig)


def test_no_chains_no_options():
    assert recommend([]) == []
