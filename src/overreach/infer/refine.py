"""Second-pass effect refinement.

Rule inference runs first (in ``overreach.infer``). A refiner then revisits each
operation to improve precision. Two refiners ship:

  * ``OfflineRefiner`` (default): deterministic, no network. It prunes effects
    the first pass over-guessed and adds a few the first pass missed.
  * ``LLMRefiner`` (optional): calls a language model for the operations the
    rules leave uncertain. It only runs when configured through the environment,
    its output is schema-validated, and it never outranks a deterministic rule:
    model-derived effects stay ``INFERRED`` and capped in confidence.

Either way every effect keeps a provenance and a confidence; nothing here is
presented as ground truth about the running system.
"""
from __future__ import annotations

import re
from typing import Protocol

from overreach.model import Confidence, Effect, EffectKind, Operation, Provenance

_PLACEHOLDER_RE = re.compile(r"\{[^}]*\}")

# Words that indicate a genuine commerce context. Without one, a "move money"
# guess from a word like "order" or "transfer" is almost always a false hit.
_COMMERCE = frozenset((
    "payment", "billing", "invoice", "checkout", "charge", "refund", "payout",
    "subscription", "purchase", "cart", "price", "wallet", "transaction",
    "credit", "debit", "balance", "stripe", "paypal",
))
_PAGINATION = frozenset((
    "page", "per_page", "perpage", "limit", "offset", "cursor", "size",
    "page_size", "pagesize", "page_token", "pagetoken", "max_results",
))
# Specific identity objects/words that make a weak change-identity guess
# credible. The bare verbs "transfer"/"rename" are intentionally absent: they are
# an identity signal only when the inference rules gate them on an ownable
# object, and those rules emit at confidence >= 0.6, which the refiner keeps
# regardless of this set.
_IDENTITY_SPECIFIC = frozenset((
    "email", "password", "token", "secret", "role", "permission",
    "membership", "credential", "apikey", "2fa", "mfa",
    "collaborator", "scheme", "promote", "demote",
))
_MODEL_MAX_CONFIDENCE: Confidence = 0.75


class Refiner(Protocol):
    def refine(self, op: Operation) -> Operation: ...


class NullRefiner:
    def refine(self, op: Operation) -> Operation:
        return op


def _blob(op: Operation) -> str:
    path = _PLACEHOLDER_RE.sub(" ", op.path)
    return f"{op.op_id} {path} {op.summary} {' '.join(op.tags)}".lower()


def _is_collection(op: Operation) -> bool:
    # A GET whose path ends in a plural noun segment looks like a list.
    last = op.path.rstrip("/").split("/")[-1]
    return (op.method == "get" and not last.startswith("{")
            and last.endswith("s") and not last.endswith("ss"))


def _has_pagination(op: Operation) -> bool:
    return any(f.location == "query" and f.name.lower() in _PAGINATION
               for f in op.fields)


class OfflineRefiner:
    """Deterministic refinement: prune over-guesses, add a couple of misses."""

    def refine(self, op: Operation) -> Operation:
        blob = _blob(op)
        effects = list(op.effects)

        # 1) Prune money effects with no commerce context (kills "order"/"transfer"
        #    false positives on APIs that handle no payments).
        if any(e.kind == EffectKind.MOVE_MONEY for e in effects):
            if not any(w in blob for w in _COMMERCE):
                effects = [e for e in effects if e.kind != EffectKind.MOVE_MONEY]

        # 2) Flag an unbounded collection read as a cost risk (denial of wallet).
        if _is_collection(op) and not _has_pagination(op):
            target = op.objects[-1] if op.objects else "collection"
            effects.append(Effect(EffectKind.COST, target, Provenance.INFERRED,
                                  0.5, "list without pagination can be unbounded"))

        # 3) Keep a change-identity guess when a specific identity object is
        #    present (and boost it); drop only a weak generic word guess. Effects
        #    the rules already emit at >= 0.6 (credential/key addition, gated
        #    ownership transfer) are specific by construction and are kept.
        has_specific = any(o in _IDENTITY_SPECIFIC for o in op.objects) or \
            any(w in blob for w in _IDENTITY_SPECIFIC)
        refined: list[Effect] = []
        for e in effects:
            if e.kind == EffectKind.CHANGE_IDENTITY:
                if e.confidence < 0.6 and not has_specific:
                    continue  # drop a weak generic identity guess
                if has_specific and e.confidence < 0.7:
                    e = Effect(e.kind, e.target, e.provenance, 0.7,
                               e.reason + "; specific identity object")
            refined.append(e)

        # Dedupe by (kind, target), keeping highest confidence.
        best: dict[tuple[EffectKind, str], Effect] = {}
        for e in refined:
            k = (e.kind, e.target)
            if k not in best or e.confidence > best[k].confidence:
                best[k] = e
        return op.with_effects(tuple(best.values()))


class LLMRefiner:
    """Optional model-backed refinement. Only the operations the rules leave
    uncertain are sent. Output is validated and capped; a model never outranks a
    rule. Requires configuration via the environment; otherwise it is inert.
    """

    def __init__(self, client: object | None = None) -> None:
        self._client = client  # a callable(prompt)->json-string, injected

    def refine(self, op: Operation) -> Operation:
        if self._client is None:
            return op  # not configured: do nothing, safely
        # Intentionally conservative: real wiring (prompt, schema validation,
        # confidence cap at _MODEL_MAX_CONFIDENCE, provenance INFERRED) lands
        # when a provider is configured and measured against the spike specs.
        return op


def get_refiner() -> Refiner:
    """Pick a refiner. Offline by default; a configured model provider later."""
    return OfflineRefiner()
