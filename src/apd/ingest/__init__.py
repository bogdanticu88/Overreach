"""Safe OpenAPI ingest.

Loads a spec from JSON or YAML into the internal ``Api`` model. Hostile by
assumption: nothing is executed, external ``$ref`` targets are never fetched,
YAML is parsed in safe mode only, and size/depth limits bound the work.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from apd.model import Api, Field, Operation, Origin

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
_MAX_BYTES = 32 * 1024 * 1024
_MAX_REF_DEPTH = 64
_EXIT_FORMATS = ("uri", "url", "uri-reference", "email", "hostname", "idn-email")
_EXIT_NAME_HINTS = (
    "url", "uri", "callback", "webhook", "redirect", "destination",
    "endpoint", "email", "target_url", "notify",
)


class IngestError(Exception):
    pass


@dataclass(frozen=True)
class _Ref:
    pointer: str


def _safe_load(text: str) -> Any:
    # json.loads first (faster, stricter); fall back to safe YAML.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


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


def _resolve(node: Any, root: dict[str, Any], depth: int = 0) -> Any:
    """Resolve internal $ref only. External refs become an inert marker."""
    if depth > _MAX_REF_DEPTH:
        return {}
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if not ref.startswith("#/"):
                return {"_external_ref": ref}  # never fetched
            target: Any = root
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict) and part in target:
                    target = target[part]
                else:
                    return {}
            return _resolve(target, root, depth + 1)
        return {k: _resolve(v, root, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, root, depth + 1) for v in node]
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


def _collect_fields(op: dict[str, Any], root: dict[str, Any]) -> tuple[Field, ...]:
    out: list[Field] = []
    for p in op.get("parameters", []) or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name", ""))
        loc = str(p.get("in", ""))
        sch = p.get("schema") or {}
        if name:
            out.append(Field(name, loc, _field_origin(name),
                             _is_exit_field(name, sch), str(sch.get("type", ""))))
    body = op.get("requestBody") or {}
    content = (body.get("content") or {}) if isinstance(body, dict) else {}
    for media in content.values():
        sch = (media or {}).get("schema") or {}
        props = sch.get("properties") or {}
        for pname, psch in props.items():
            if not isinstance(psch, dict):
                continue
            out.append(Field(str(pname), "body", _field_origin(str(pname)),
                             _is_exit_field(str(pname), psch),
                             str(psch.get("type", ""))))
    return tuple(out)


def _build(doc: dict[str, Any], raw: str) -> Api:
    root = doc
    info = doc.get("info") or {}
    title = str(info.get("title", "unknown"))
    version = str(info.get("version", ""))
    warnings: list[str] = []
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
            op = _resolve(raw_op, root)
            op_id = str(op.get("operationId") or f"{method}_{path}")
            tags = tuple(str(t) for t in (op.get("tags") or []) if isinstance(t, str))
            summary = str(op.get("summary", ""))
            schemes: list[str] = []
            for sec in op.get("security", []) or []:
                if isinstance(sec, dict):
                    schemes.extend(sec.keys())
            fields = _collect_fields(op, root)
            ops.append(Operation(
                op_id=op_id, method=method, path=path, tags=tags,
                summary=summary, auth_schemes=tuple(schemes), fields=fields,
            ))
    if not ops:
        warnings.append("no operations found")
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]
    return Api(title=title, version=version, operations=tuple(ops),
               source_hash=digest, warnings=tuple(warnings))
