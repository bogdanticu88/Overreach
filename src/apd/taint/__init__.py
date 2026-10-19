"""Taint pairing.

Finds places where one operation writes an object and another reads it back,
which is where attacker-written text can reach an agent. v0.1 pairs by the
object nouns in the path; schema-reference pairing is a later refinement.

This module does not decide *who* wrote the data (that needs the boundaries
file); it only finds the write -> read links and the fields that look like
free text an outside party could set.
"""
from __future__ import annotations

from dataclasses import dataclass

from apd.model import Api, EffectKind, Operation

_FREE_TEXT_HINTS = ("body", "comment", "description", "text", "message",
                    "content", "note", "title", "name", "subject", "bio")


@dataclass(frozen=True, slots=True)
class WriteReadLink:
    obj: str
    writer: str          # operation key that writes the object
    reader: str          # operation key that reads it back
    free_text_fields: tuple[str, ...]


def _writes(op: Operation) -> bool:
    return any(e.kind in (EffectKind.WRITE, EffectKind.CHANGE_IDENTITY)
               for e in op.effects)


def _reads(op: Operation) -> bool:
    return any(e.kind == EffectKind.READ for e in op.effects)


def _free_text(op: Operation) -> tuple[str, ...]:
    out = [f.name for f in op.fields
           if f.location == "body" and f.schema_type in ("string", "")
           and any(h in f.name.lower() for h in _FREE_TEXT_HINTS)]
    return tuple(dict.fromkeys(out))


def _primary_object(op: Operation) -> str | None:
    """The specific resource an operation acts on: the last noun in its path.

    Pairing taint on this, rather than on any shared noun, stops a broad
    container like ``repo`` from linking every writer to every reader.
    """
    return op.objects[-1] if op.objects else None


def find_links(api: Api) -> list[WriteReadLink]:
    writers: dict[str, list[Operation]] = {}
    readers: dict[str, list[Operation]] = {}
    for op in api.operations:
        obj = _primary_object(op)
        if obj is None:
            continue
        if _writes(op):
            writers.setdefault(obj, []).append(op)
        if _reads(op):
            readers.setdefault(obj, []).append(op)
    links: list[WriteReadLink] = []
    for obj, ws in writers.items():
        rs = readers.get(obj, [])
        if not rs:
            continue
        for w in ws:
            ft = _free_text(w)
            if not ft:
                continue
            for r in rs:
                links.append(WriteReadLink(obj, w.key, r.key, ft))
    return links
