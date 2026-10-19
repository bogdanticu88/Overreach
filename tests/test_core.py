from __future__ import annotations

from pathlib import Path

from overreach.infer import infer_api
from overreach.ingest import load_path, load_text
from overreach.model import EffectKind, Provenance
from overreach.taint import find_links

FIX = Path(__file__).parent / "fixtures" / "tiny.json"


def _api():
    return infer_api(load_path(FIX))


def test_parses_all_operations():
    api = _api()
    assert len(api.operations) == 5
    assert api.by_key()["POST /repos/{owner}/{repo}/hooks"].op_id == "createHook"


def test_every_effect_has_provenance_and_confidence():
    api = _api()
    for op in api.operations:
        for e in op.effects:
            assert e.provenance in Provenance
            assert 0.0 <= e.confidence <= 1.0


def test_exit_field_detected():
    api = _api()
    hook = api.by_key()["POST /repos/{owner}/{repo}/hooks"]
    assert any(f.is_exit for f in hook.fields)
    assert any(e.kind == EffectKind.SEND_OUT for e in hook.effects)


def test_identity_change_detected():
    api = _api()
    pw = api.by_key()["PUT /user/password"]
    assert any(e.kind == EffectKind.CHANGE_IDENTITY for e in pw.effects)


def test_write_read_link_on_comment():
    # The comment body is written by one op and read by another; the link is
    # keyed on the specific object (comment), not the container (issue).
    api = _api()
    links = find_links(api)
    objs = {lk.obj for lk in links}
    assert "comment" in objs
    comment_links = [lk for lk in links if lk.obj == "comment"]
    assert any("body" in lk.free_text_fields for lk in comment_links)


def test_external_ref_not_fetched():
    spec = """
    {"openapi":"3.0.0","info":{"title":"x","version":"1"},
     "paths":{"/a":{"get":{"operationId":"a",
       "parameters":[{"$ref":"https://evil.example/boom.json#/x"}],
       "responses":{"200":{"description":"ok"}}}}}}
    """
    api = load_text(spec)
    assert len(api.operations) == 1  # did not crash, did not fetch


def test_no_paths_warns():
    api = load_text('{"openapi":"3.0.0","info":{"title":"x","version":"1"},"paths":{}}')
    assert "no operations found" in api.warnings
