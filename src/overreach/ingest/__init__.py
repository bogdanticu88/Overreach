"""Safe OpenAPI ingest.

Loads a spec from JSON or YAML into the internal ``Api`` model. Hostile by
assumption: nothing is executed, external ``$ref`` targets are never fetched,
YAML is parsed in safe mode only, and size / depth / total-work limits bound the
work so a crafted spec cannot exhaust memory or CPU.

Schema walking descends nested objects, array ``items`` and ``allOf`` /
``oneOf`` / ``anyOf`` compositions so that exit fields (URL / callback / email)
and free-text fields buried inside composed schemas are not missed. Every
unsupported or ambiguous construct the walker meets is recorded as a warning on
the resulting ``Api`` rather than silently dropped.
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
_MAX_REF_DEPTH = 64
# Total nodes the ref-resolver may expand for one document. A spec that repeats
# references with wide fan-out can amplify node count super-linearly even within
# the depth bound; this caps the total work regardless of shape.
_MAX_RESOLVE_NODES = 200_000
# Bound on how deep the schema-field walker descends into nested objects /
# arrays / compositions, and how many schema nodes it will visit per operation.
_MAX_SCHEMA_DEPTH = 24
_MAX_SCHEMA_NODES = 10_000
_EXIT_FORMATS = ("uri", "url", "uri-reference", "email", "hostname", "idn-email")
_EXIT_NAME_HINTS = (
    "url", "uri", "callback", "webhook", "redirect", "destination",
    "endpoint", "email", "target_url", "notify",
)


class IngestError(Exception):
    pass


@dataclass
class _Ctx:
    """Mutable per-document state for bounded resolution and warnings."""
    root: dict[str, Any]
    nodes: int = 0                      # resolver nodes expanded so far
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


def _resolve(node: Any, ctx: _Ctx, depth: int = 0) -> Any:
    """Resolve internal ``$ref`` only, within depth and total-node budgets.

    External refs become an inert marker and are never fetched. A ref pointer
    that does not resolve, or work beyond the budgets, is recorded as a warning
    and the subtree is dropped (returned as ``{}``) rather than raising.
    """
    if depth > _MAX_REF_DEPTH:
        ctx.warn(f"schema nesting exceeded depth limit ({_MAX_REF_DEPTH}); truncated")
        return {}
    ctx.nodes += 1
    if ctx.nodes > _MAX_RESOLVE_NODES:
        ctx.warn(f"$ref expansion exceeded node budget ({_MAX_RESOLVE_NODES}); truncated")
        return {}
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/"):
                ctx.warn(f"external $ref not resolved (never fetched): {ref}")
                return {"_external_ref": ref}
            target: Any = ctx.root
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict) and part in target:
                    target = target[part]
                else:
                    ctx.warn(f"internal $ref did not resolve: {ref}")
                    return {}
            return _resolve(target, ctx, depth + 1)
        return {k: _resolve(v, ctx, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, ctx, depth + 1) for v in node]
    return node


def _field_origin(name: str) -> Origin:
    # A conservative default; real origin is refined later by taint analysis.
    return Origin.UNKNOWN


def _is_exit_field(name: str, schema: dict[str, Any]) -> bool:
    fmt = str(schema.get("format", "")).lower()
    if fmt in _EXIT_FORMATS:
        return True
    low = name.lower()
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
    """Accumulator for the schema-field walker (bounded by node count)."""
    out: list[Field]
    nodes: int = 0
    ctx: _Ctx | None = None


def _walk_schema(schema: Any, name: str, location: str, w: _Walk, depth: int) -> None:
    """Descend a (ref-resolved) schema, emitting a Field for each leaf property.

    Handles nested objects (``properties``), arrays (``items``) and the
    ``allOf`` / ``oneOf`` / ``anyOf`` compositions. ``name`` is the property
    name under which this schema sits ("" at the body root). Bounded by
    ``_MAX_SCHEMA_DEPTH`` and ``_MAX_SCHEMA_NODES``.
    """
    if not isinstance(schema, dict):
        return
    w.nodes += 1
    if w.nodes > _MAX_SCHEMA_NODES:
        if w.ctx:
            w.ctx.warn(f"schema too large to walk fully ({_MAX_SCHEMA_NODES} nodes); truncated")
        return
    if depth > _MAX_SCHEMA_DEPTH:
        if w.ctx:
            w.ctx.warn(f"schema nested beyond {_MAX_SCHEMA_DEPTH} levels; truncated")
        return

    # Compositions: walk every branch. oneOf/anyOf branches keep the same name.
    for key in ("allOf", "oneOf", "anyOf"):
        sub = schema.get(key)
        if isinstance(sub, list):
            if key in ("oneOf", "anyOf") and w.ctx:
                w.ctx.warn(f"ambiguous '{key}' schema on '{name or '<body>'}'; "
                           "fields from all branches are considered")
            for s in sub:
                _walk_schema(s, name, location, w, depth + 1)

    props = schema.get("properties")
    if isinstance(props, dict):
        for pname, psch in props.items():
            if not isinstance(psch, dict):
                continue
            pn = str(pname)
            ptype = _leaf_type(psch)
            # Record this property as a field (leaf or not); its type and name
            # drive exit / free-text detection downstream.
            w.out.append(Field(pn, location, _field_origin(pn),
                               _is_exit_field(pn, psch), ptype))
            # Descend into nested objects and array element schemas so that
            # exit / free-text fields deeper in the tree are also recorded.
            if ptype == "object" or "properties" in psch or any(
                    k in psch for k in ("allOf", "oneOf", "anyOf")):
                _walk_schema(psch, pn, location, w, depth + 1)
            items = psch.get("items")
            if isinstance(items, dict):
                _walk_schema(items, pn, location, w, depth + 1)

    # A top-level array body: walk its element schema under the body name.
    items = schema.get("items")
    if isinstance(items, dict) and "properties" not in schema:
        _walk_schema(items, name, location, w, depth + 1)


def _collect_fields(op: dict[str, Any], ctx: _Ctx) -> tuple[Field, ...]:
    out: list[Field] = []
    for p in op.get("parameters", []) or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name", ""))
        loc = str(p.get("in", ""))
        sch = p.get("schema") or {}
        if name:
            out.append(Field(name, loc, _field_origin(name),
                             _is_exit_field(name, sch), _leaf_type(sch)))
    body = op.get("requestBody") or {}
    content = (body.get("content") or {}) if isinstance(body, dict) else {}
    for media in content.values():
        sch = (media or {}).get("schema") or {}
        if isinstance(sch, dict):
            w = _Walk(out=out, ctx=ctx)
            _walk_schema(sch, "", "body", w, 0)
    # Dedupe by (name, location) keeping the first (an exit hit wins a tie).
    best: dict[tuple[str, str], Field] = {}
    for f in out:
        k = (f.name, f.location)
        if k not in best or (f.is_exit and not best[k].is_exit):
            best[k] = f
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
            op = _resolve(raw_op, ctx)
            op_id = str(op.get("operationId") or f"{method}_{path}")
            tags = tuple(str(t) for t in (op.get("tags") or []) if isinstance(t, str))
            summary = str(op.get("summary", ""))
            schemes: list[str] = []
            for sec in op.get("security", []) or []:
                if isinstance(sec, dict):
                    schemes.extend(sec.keys())
            fields = _collect_fields(op, ctx)
            ops.append(Operation(
                op_id=op_id, method=method, path=path, tags=tags,
                summary=summary, auth_schemes=tuple(schemes), fields=fields,
            ))
    if not ops:
        ctx.warn("no operations found")
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]
    return Api(title=title, version=version, operations=tuple(ops),
               source_hash=digest, warnings=tuple(ctx.warnings))
