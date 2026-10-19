"""Core types for the effect model.

Everything here is immutable and carries its own provenance and confidence.
Two invariants hold across the whole engine:

  * A derived value never has higher confidence than what it came from.
  * A derived value never drops the provenance of what it came from.

Nothing in this module reads the network or executes anything from a spec.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Provenance(str, Enum):
    """Where a claim about an effect came from."""

    DECLARED = "declared"   # the spec says so explicitly
    INFERRED = "inferred"   # a rule or model predicted it
    OBSERVED = "observed"   # seen during execution (replay only)


class Origin(str, Enum):
    """Who can write the data in a field."""

    THIS_USER = "this_user"
    OTHER_USER = "other_user"
    OUTSIDER = "outsider"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EffectKind(str, Enum):
    """What an operation does, beyond its HTTP verb."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND_OUT = "send_out"          # pushes data to a destination the caller names
    MOVE_MONEY = "move_money"
    CHANGE_IDENTITY = "change_identity"  # email, password, token, membership
    IRREVERSIBLE = "irreversible"
    COST = "cost"                  # can run up API or model spend (e.g. unbounded list)


# Confidence is a plain float in [0, 1]. Declared facts are 1.0.
Confidence = float


@dataclass(frozen=True, slots=True)
class Effect:
    kind: EffectKind
    target: str                      # object type the effect acts on, e.g. "Repository"
    provenance: Provenance
    confidence: Confidence
    reason: str                      # short human-readable justification

    def downgraded_to(self, cap: Confidence) -> "Effect":
        """Return a copy whose confidence is no higher than ``cap``."""
        if self.confidence <= cap:
            return self
        return Effect(self.kind, self.target, self.provenance, cap, self.reason)


@dataclass(frozen=True, slots=True)
class Field:
    name: str                        # dotted path, e.g. "Comment.body"
    location: str                    # "body", "query", "path", "header", "response"
    origin: Origin
    is_exit: bool = False            # accepts a URL, email, callback or destination
    schema_type: str = ""


@dataclass(frozen=True, slots=True)
class Operation:
    op_id: str
    method: str                      # lower case: get, post, put, patch, delete
    path: str
    tags: tuple[str, ...] = ()
    summary: str = ""
    auth_schemes: tuple[str, ...] = ()
    fields: tuple[Field, ...] = ()
    effects: tuple[Effect, ...] = ()
    objects: tuple[str, ...] = ()    # object types this operation names

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def with_effects(self, effects: tuple[Effect, ...]) -> "Operation":
        return Operation(
            self.op_id, self.method, self.path, self.tags, self.summary,
            self.auth_schemes, self.fields, effects, self.objects,
        )


@dataclass(frozen=True, slots=True)
class Api:
    """A parsed API: the unit the rest of the engine reasons over."""

    title: str
    version: str
    operations: tuple[Operation, ...]
    source_hash: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def by_key(self) -> dict[str, Operation]:
        return {op.key: op for op in self.operations}
