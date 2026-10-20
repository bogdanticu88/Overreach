"""Rule-based effect inference.

Deterministic rules run first and carry provenance INFERRED with a confidence
below 1.0 (declared facts, when a spec ever gives them, would be 1.0). A model
pass (not in this module) only touches operations these rules leave uncertain.

No network, no execution. Pure functions over the parsed model.
"""
from __future__ import annotations

import re

from overreach.model import Api, Effect, EffectKind, Operation, Provenance

# Verb hints found in path segments or operationIds.
_DESTROY_WORDS = ("delete", "remove", "purge", "destroy", "revoke", "wipe")
_IDENTITY_WORDS = ("password", "email", "token", "secret", "login",
                   "membership", "role", "permission", "collaborator", "scheme",
                   "2fa", "mfa", "credential", "apikey", "api_key",
                   "promote", "demote", "transfer", "rename")
_MONEY_WORDS = ("payment", "charge", "invoice", "refund", "payout",
                "subscription", "billing", "transfer", "order")
# Path-object nouns for credential/key material. Adding one of these is
# persistent access that outlives the session (an SSH/GPG/deploy key, an app
# password), which is a takeover-class effect the lexical word list misses.
# Matched on the path-derived object noun, not a blob substring, so "monkey" or
# "keyword" cannot trigger it.
_CREDENTIAL_OBJECTS = frozenset((
    "key", "gpg_key", "ssh_key", "deploy_key", "credential", "secret",
))
_IRREVERSIBLE_WORDS = ("delete", "purge", "destroy", "transfer", "merge",
                       "archive", "finalize", "finalise")
_OBJECT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


_PATH_STOPWORDS = frozenset((
    "api", "v1", "v2", "v3", "v4", "rest", "latest", "public",
))


def _objects_in_path(path: str) -> tuple[str, ...]:
    # Collection nouns in a path: /repos/{owner}/{repo}/hooks -> repo, hook
    out: list[str] = []
    for seg in path.strip("/").split("/"):
        if seg.startswith("{") or not seg:
            continue
        m = _OBJECT_RE.match(seg)
        if not m:
            continue
        noun = (m.group(0).rstrip("s") or m.group(0)).lower()
        if noun in _PATH_STOPWORDS:
            continue
        out.append(noun)
    return tuple(dict.fromkeys(out))  # dedupe, keep order


_PLACEHOLDER_RE = re.compile(r"\{[^}]*\}")


def _blob(op: Operation) -> str:
    # Strip {placeholders}: a path parameter name (e.g. {owner}) is not a
    # signal about what the operation does.
    path = _PLACEHOLDER_RE.sub(" ", op.path)
    return f"{op.op_id} {path} {op.summary} {' '.join(op.tags)}".lower()


def infer_operation(op: Operation) -> Operation:
    objects = _objects_in_path(op.path)
    target = objects[-1] if objects else "resource"
    blob = _blob(op)
    effects: list[Effect] = []

    # Base effect from the HTTP method. High but not certain: specs lie.
    method = op.method
    if method == "get":
        effects.append(Effect(EffectKind.READ, target, Provenance.INFERRED, 0.9,
                              "GET implies read"))
    elif method in ("post", "put", "patch"):
        effects.append(Effect(EffectKind.WRITE, target, Provenance.INFERRED, 0.85,
                              f"{method.upper()} implies write"))
    elif method == "delete":
        effects.append(Effect(EffectKind.DELETE, target, Provenance.INFERRED, 0.9,
                              "DELETE implies delete"))
        effects.append(Effect(EffectKind.IRREVERSIBLE, target, Provenance.INFERRED,
                              0.6, "delete is usually irreversible"))

    # Lexical overrides. Lower confidence; a word is a weaker signal than a verb.
    if any(w in blob for w in _DESTROY_WORDS) and method != "get":
        effects.append(Effect(EffectKind.DELETE, target, Provenance.INFERRED, 0.6,
                              "destructive wording"))
    # Identity and money effects are state changes, so they require a writing
    # method. A GET on a resource merely *named* "token"/"payment" is a read, not
    # an identity change or a money movement (this removed a class of false
    # fraud/takeover terminals on Stripe and DigitalOcean reads).
    if method != "get" and any(w in blob for w in _IDENTITY_WORDS):
        effects.append(Effect(EffectKind.CHANGE_IDENTITY, target,
                              Provenance.INFERRED, 0.55, "identity-related wording"))
    # Adding credential/key material (non-GET) is persistent access.
    if method != "get" and any(o in _CREDENTIAL_OBJECTS for o in objects):
        effects.append(Effect(EffectKind.CHANGE_IDENTITY, target,
                              Provenance.INFERRED, 0.6,
                              "adds credential/key material (persistent access)"))
    if method != "get" and any(w in blob for w in _MONEY_WORDS):
        effects.append(Effect(EffectKind.MOVE_MONEY, target, Provenance.INFERRED,
                              0.5, "money-related wording"))
    if any(w in blob for w in _IRREVERSIBLE_WORDS) and method != "get":
        effects.append(Effect(EffectKind.IRREVERSIBLE, target, Provenance.INFERRED,
                              0.5, "wording suggests no undo"))

    # A writable exit field means the caller can name where data goes.
    if method != "get" and any(f.is_exit for f in op.fields):
        exit_names = ", ".join(f.name for f in op.fields if f.is_exit)
        effects.append(Effect(EffectKind.SEND_OUT, target, Provenance.INFERRED, 0.6,
                              f"caller-supplied destination: {exit_names}"))

    # Dedupe by (kind, target) keeping the highest confidence.
    best: dict[tuple[EffectKind, str], Effect] = {}
    for e in effects:
        k = (e.kind, e.target)
        if k not in best or e.confidence > best[k].confidence:
            best[k] = e
    return Operation(
        op.op_id, op.method, op.path, op.tags, op.summary, op.auth_schemes,
        op.fields, tuple(best.values()), objects,
    )


def uncertain_operations(api: Api, threshold: float = 0.6) -> list[Operation]:
    """Operations whose strongest non-base effect is weak: candidates for a model pass."""
    out: list[Operation] = []
    for op in api.operations:
        extra = [e for e in op.effects
                 if e.kind not in (EffectKind.READ, EffectKind.WRITE, EffectKind.DELETE)]
        if not extra or max(e.confidence for e in extra) < threshold:
            out.append(op)
    return out


def infer_api(api: Api, *, refine: bool = True) -> Api:
    """Run rule inference, then a refinement pass (offline by default)."""
    enriched = tuple(infer_operation(op) for op in api.operations)
    if refine:
        from overreach.infer.refine import get_refiner
        refiner = get_refiner()
        enriched = tuple(refiner.refine(op) for op in enriched)
    return Api(api.title, api.version, enriched, api.source_hash, api.warnings)
