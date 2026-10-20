"""Safe OpenAPI ingest.

Loads a spec from JSON or YAML into the internal ``Api`` model. Hostile by
assumption: nothing is executed, external ``$ref`` targets are never fetched,
YAML is parsed in safe mode only, and size / depth / per-operation node limits
bound the work so a crafted spec cannot exhaust memory or CPU.

References are resolved lazily and only where fields are read (an operation's
parameters and request body), never by inlining the whole operation. This keeps
work linear in the parts that matter even on large, heavily ``$ref``-ed specs,
instead of expanding every response schema. Cycles are caught by tracking the
``$ref`` pointers on the current ancestor chain.

Schema walking descends nested objects, array ``items`` and ``allOf`` /
``oneOf`` / ``anyOf`` compositions so that exit fields (URL / callback / email)
and free-text fields buried inside composed schemas are not missed. Every
unsupported or ambiguous construct the walker meets is recorded as a warning.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from overreach.model import Api, Field, Operation, Origin

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
_MAX_BYTES = 32 * 1024 * 1024
# Longest chain of $ref -> $ref hops we will follow before giving up.
_MAX_REF_DEPTH = 64
# Per-operation bounds for the field walker, so one pathological operation
# cannot starve the rest of the document or run unbounded.
_MAX_SCHEMA_DEPTH = 48
_MAX_SCHEMA_NODES = 20_000
_EXIT_FORMATS = ("uri", "url", "uri-reference", "email", "hostname", "idn-email")
# A field whose name says it carries data OUT to a caller-named destination
# (a webhook payload sink, a notify/callback target, an email).
_EXIT_NAME_HINTS = (
    "url", "uri", "callback", "webhook", "destination",
    "endpoint", "email", "target_url", "notify",
)
# URL-shaped fields that are NOT attacker-directed data egress: OAuth/OIDC
# provider endpoints, browser redirect/return targets, and provider-fixed links.
# A field matching one of these is not treated as an exfiltration exit even
# though it is URL-shaped (removes a class of false exfil terminals, e.g. Stripe
# dispute-evidence links and DigitalOcean oauth_authorize_url/oauth_token_url).
_NONEGRESS_URL_HINTS = (
    "authorize", "token_url", "tokenurl", "return", "redirect", "success",
    "cancel", "login", "logout", "issuer", "jwks", "policy", "receipt",
    "terms", "privacy",
)


class IngestError(Exception):
    pass


@dataclass
class _Ctx:
    """Per-document state: the root (for pointer resolution) and warnings."""
    root: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    _seen: set[str] = field(default_factory=set)

    def warn(self, msg: str) -> None:
        if msg not in self._seen:
            self._seen.add(msg)
            self.warnings.append(msg)


def _safe_load(text: str) -> Any:
    # json.loads first (faster, stricter); fall back to safe YAML.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise IngestError(f"spec is neither valid JSON nor safe YAML: {exc}") from exc


def load_text(text: str, *, origin_hint: Origin = Origin.UNKNOWN) -> Api:
    if len(text.encode("utf-8", "ignore")) > _MAX_BYTES:
        raise IngestError("spec exceeds size limit")
    doc = _safe_load(text)
    if not isinstance(doc, dict):
        raise IngestError("top level of spec is not a mapping")
    return _build(doc, text)


def load_path(path: str | Path) -> Api:
    p = Path(path)
    # Reject by size on disk before reading, so an oversized file is never
    # loaded into memory in full.
    try:
        if p.stat().st_size > _MAX_BYTES:
            raise IngestError("spec exceeds size limit")
    except OSError as exc:
        raise IngestError(f"cannot stat spec: {exc}") from exc
    return load_text(p.read_text(encoding="utf-8", errors="replace"))


def merge_docs(docs: list[dict[str, Any]], title: str, version: str) -> Api:
    """Merge several OpenAPI fragments (e.g. Mattermost's split YAML)."""
    paths: dict[str, Any] = {}
    components: dict[str, Any] = {"schemas": {}}
    for d in docs:
        # Fragments may hold paths under "paths" or as top-level "/..." keys.
        path_maps = [d.get("paths") or {}]
        path_maps.append({k: v for k, v in d.items()
                          if isinstance(k, str) and k.startswith("/")})
        for pm in path_maps:
            for k, v in pm.items():
                if isinstance(k, str) and k.startswith("/") and isinstance(v, dict):
                    paths.setdefault(k, {}).update(v)
        comp = d.get("components") or {}
        for sk, sv in (comp.get("schemas") or {}).items():
            components["schemas"].setdefault(sk, sv)
    merged = {"openapi": "3.0", "info": {"title": title, "version": version},
              "paths": paths, "components": components}
    return _build(merged, json.dumps(merged, sort_keys=True))


def _deref(node: Any, ctx: _Ctx, seen: frozenset[str]) -> tuple[Any, frozenset[str]]:
    """Follow a chain of internal ``$ref`` hops to the node they point at.

    External refs are never fetched (warned, treated as empty). A pointer that
    does not resolve, a cycle, or a ref chain longer than the bound all resolve
    to ``{}``. Returns the resolved node and the updated ancestor-pointer set.
    """
    hops = 0
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if not ref.startswith("#/"):
            ctx.warn(f"external $ref not resolved (never fetched): {ref}")
            return {}, seen
        if ref in seen:                 # cycle on the ancestor chain
            return {}, seen
        hops += 1
        if hops > _MAX_REF_DEPTH:
            ctx.warn(f"$ref chain exceeded {_MAX_REF_DEPTH} hops; truncated")
            return {}, seen
        target: Any = ctx.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict) and part in target:
                target = target[part]
            else:
                ctx.warn(f"internal $ref did not resolve: {ref}")
                return {}, seen
        seen = seen | {ref}
        node = target
    return node, seen


def _field_origin(name: str) -> Origin:
    # A conservative default; real origin is refined later by taint analysis.
    return Origin.UNKNOWN


def _is_exit_field(name: str, schema: dict[str, Any]) -> bool:
    low = name.lower()
    # A provider/redirect URL is not attacker-directed egress, even if it is
    # URL-shaped by name or format.
    if any(h in low for h in _NONEGRESS_URL_HINTS):
        return False
    # An email that names a subject's stored address (customer_email_address,
    # billing_email, owner_email) is a data attribute, not a send-to
    # destination. A bare "email" or a "notify"/"recipient" email still counts.
    if "email" in low and ("_address" in low or any(
            q in low for q in ("customer", "billing", "owner", "holder",
                               "sender", "from_", "contact"))):
        return False
    if str(schema.get("format", "")).lower() in _EXIT_FORMATS:
        return True
    return any(h in low for h in _EXIT_NAME_HINTS)


def _leaf_type(schema: dict[str, Any]) -> str:
    t = schema.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):  # OpenAPI 3.1 nullable: ["string","null"]
        for x in t:
            if isinstance(x, str) and x != "null":
                return x
    return ""


@dataclass
class _Walk:
    """Accumulator for the schema-field walker, bounded per operation."""
    out: list[Field]
    ctx: _Ctx
    nodes: int = 0
    # True once a oneOf/anyOf branch was entered: fields below are only present
    # in *some* valid requests, not guaranteed in every request.
    optional_context: bool = False


def _walk_schema(schema: Any, name: str, location: str, w: _Walk, depth: int,
                 seen: frozenset[str], optional: bool = False) -> None:
    """Descend a schema, resolving ``$ref`` lazily, emitting a Field per leaf
    property. Handles nested objects, array ``items`` and allOf/oneOf/anyOf.
    ``optional`` marks fields reached only through a oneOf/anyOf branch."""
    schema, seen = _deref(schema, w.ctx, seen)
    if not isinstance(schema, dict):
        return
    w.nodes += 1
    if w.nodes > _MAX_SCHEMA_NODES:
        w.ctx.warn(f"schema too large to walk fully ({_MAX_SCHEMA_NODES} nodes); truncated")
        return
    if depth > _MAX_SCHEMA_DEPTH:
        w.ctx.warn(f"schema nested beyond {_MAX_SCHEMA_DEPTH} levels; truncated")
        return

    # allOf: every branch contributes (intersection semantics -> all present).
    for s in schema.get("allOf", []) or []:
        _walk_schema(s, name, location, w, depth + 1, seen, optional)
    # oneOf/anyOf: fields come from alternative shapes, so they are only
    # *possibly* present. Mark them optional and warn once per site.
    for key in ("oneOf", "anyOf"):
        branches = schema.get(key)
        if isinstance(branches, list) and branches:
            # Collapsed to one message per document: the per-field detail is
            # carried by each Field's required=False flag, not by a warning line.
            w.ctx.warn("spec uses oneOf/anyOf: fields from alternative branches are "
                       "treated as possibly-present (required=False), not guaranteed")
            for s in branches:
                _walk_schema(s, name, location, w, depth + 1, seen, optional=True)

    props = schema.get("properties")
    if isinstance(props, dict):
        required = schema.get("required")
        req = set(required) if isinstance(required, list) else set()
        for pname, psch in props.items():
            psch, psub_seen = _deref(psch, w.ctx, seen)
            if not isinstance(psch, dict):
                continue
            pn = str(pname)
            # A property is only reliably present if it is in this object's
            # "required" list and not reached through an optional branch.
            opt = optional or (pn not in req)
            w.out.append(Field(pn, location, _field_origin(pn),
                               _is_exit_field(pn, psch), _leaf_type(psch),
                               required=not opt))
            if psch.get("type") == "object" or "properties" in psch or any(
                    k in psch for k in ("allOf", "oneOf", "anyOf")):
                _walk_schema(psch, pn, location, w, depth + 1, psub_seen, opt)
            items = psch.get("items")
            if isinstance(items, dict):
                _walk_schema(items, pn, location, w, depth + 1, psub_seen, opt)

    items = schema.get("items")
    if isinstance(items, dict) and "properties" not in schema:
        _walk_schema(items, name, location, w, depth + 1, seen, optional)


def _collect_fields(raw_op: dict[str, Any], ctx: _Ctx) -> tuple[Field, ...]:
    out: list[Field] = []
    empty: frozenset[str] = frozenset()
    for p in raw_op.get("parameters", []) or []:
        p, _ = _deref(p, ctx, empty)
        if not isinstance(p, dict):
            continue
        name = str(p.get("name", ""))
        loc = str(p.get("in", ""))
        sch, _ = _deref(p.get("schema") or {}, ctx, empty)
        sch = sch if isinstance(sch, dict) else {}
        if name:
            out.append(Field(name, loc, _field_origin(name),
                             _is_exit_field(name, sch), _leaf_type(sch),
                             required=bool(p.get("required", False))))
    body, _ = _deref(raw_op.get("requestBody") or {}, ctx, empty)
    content = (body.get("content") or {}) if isinstance(body, dict) else {}
    w = _Walk(out=out, ctx=ctx)
    for media in content.values():
        sch = (media or {}).get("schema") or {}
        if isinstance(sch, dict):
            _walk_schema(sch, "", "body", w, 0, empty)
    # Dedupe by (name, location); an exit hit and a required hit win ties.
    best: dict[tuple[str, str], Field] = {}
    for f in out:
        k = (f.name, f.location)
        cur = best.get(k)
        if cur is None:
            best[k] = f
        else:
            best[k] = Field(f.name, f.location, f.origin,
                            f.is_exit or cur.is_exit, f.schema_type or cur.schema_type,
                            required=f.required or cur.required)
    return tuple(best.values())


def _build(doc: dict[str, Any], raw: str) -> Api:
    ctx = _Ctx(root=doc)
    info = doc.get("info") or {}
    title = str(info.get("title", "unknown"))
    version = str(info.get("version", ""))
    ops: list[Operation] = []
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        raise IngestError("'paths' is not a mapping")
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            raw_op = item.get(method)
            if not isinstance(raw_op, dict):
                continue
            op_id = str(raw_op.get("operationId") or f"{method}_{path}")
            tags = tuple(str(t) for t in (raw_op.get("tags") or []) if isinstance(t, str))
            summary = str(raw_op.get("summary", ""))
            schemes: list[str] = []
            for sec in raw_op.get("security", []) or []:
                if isinstance(sec, dict):
                    schemes.extend(sec.keys())
            fields = _collect_fields(raw_op, ctx)
            ops.append(Operation(
                op_id=op_id, method=method, path=path, tags=tags,
                summary=summary, auth_schemes=tuple(schemes), fields=fields,
            ))
    if not ops:
        ctx.warn("no operations found")
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]
    return Api(title=title, version=version, operations=tuple(ops),
               source_hash=digest, warnings=tuple(ctx.warnings))
