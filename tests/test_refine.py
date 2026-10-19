from __future__ import annotations

from apd.infer import infer_api, infer_operation
from apd.infer.refine import OfflineRefiner
from apd.model import Api, EffectKind, Field, Operation, Origin


def _op(method, path, fields=()):
    return infer_operation(Operation(op_id=f"{method}_{path}", method=method,
                                     path=path, fields=tuple(fields)))


def test_prunes_money_without_commerce_context():
    # "transfer" a repository is not a payment.
    op = _op("post", "/repos/{owner}/{repo}/transfer")
    assert any(e.kind == EffectKind.MOVE_MONEY for e in op.effects)
    refined = OfflineRefiner().refine(op)
    assert not any(e.kind == EffectKind.MOVE_MONEY for e in refined.effects)


def test_keeps_money_with_commerce_context():
    op = _op("post", "/billing/invoices/{id}/charge")
    refined = OfflineRefiner().refine(op)
    assert any(e.kind == EffectKind.MOVE_MONEY for e in refined.effects)


def test_flags_unbounded_list_as_cost():
    op = _op("get", "/repos/{owner}/{repo}/issues")
    refined = OfflineRefiner().refine(op)
    assert any(e.kind == EffectKind.COST for e in refined.effects)


def test_paginated_list_is_not_cost():
    op = _op("get", "/repos/{owner}/{repo}/issues",
             fields=[Field("page", "query", Origin.UNKNOWN, False, "integer")])
    refined = OfflineRefiner().refine(op)
    assert not any(e.kind == EffectKind.COST for e in refined.effects)


def test_refine_can_be_disabled():
    api = Api("t", "1", (_op("post", "/orders/{id}/transfer"),))
    on = infer_api(api, refine=True)
    off = infer_api(api, refine=False)
    money_on = any(e.kind == EffectKind.MOVE_MONEY for e in on.operations[0].effects)
    money_off = any(e.kind == EffectKind.MOVE_MONEY for e in off.operations[0].effects)
    assert money_off and not money_on
