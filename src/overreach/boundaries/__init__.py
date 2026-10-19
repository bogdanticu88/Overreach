"""The boundaries file.

An optional, declarative description of the authority around an agent: which
principal it acts as, which operations that principal may call, which fields
carry untrusted input, and which path parameter identifies a tenant.

Without it, the chain finder must assume an injected agent can call any tool,
which is noisy. With it, cross-domain reach is scoped to what the agent can
actually touch, and each chain can name the boundary it crosses. This is the
authority layer the design treats as a first-class concept.

Safe by assumption: YAML is parsed in safe mode, and the file is data, never
executed.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class Boundaries:
    acts_as: str = "agent"
    # Operation-key glob patterns the agent's principal may call. None means
    # "unknown scope": the finder falls back to assuming any tool is reachable.
    allowed_ops: tuple[str, ...] | None = None
    # Fields (by name or "Object.field") that carry untrusted, externally
    # written input. These seed and confirm entry points.
    untrusted_fields: tuple[str, ...] = field(default_factory=tuple)
    # The path parameter that identifies a tenant, e.g. "owner" or "team_id".
    tenant_param: str | None = None
    # The tenant the agent itself belongs to. When set, a tenant-scoped read
    # the agent can call is a cross-tenant data-theft risk unless the API
    # enforces ownership, which a spec almost never declares.
    agent_tenant: str | None = None

    def allows(self, op_key: str) -> bool:
        if self.allowed_ops is None:
            return True
        return any(fnmatch.fnmatch(op_key, pat) for pat in self.allowed_ops)

    def marks_untrusted(self, field_name: str) -> bool:
        low = field_name.lower()
        return any(low == u.lower() or low.endswith("." + u.lower().split(".")[-1])
                   for u in self.untrusted_fields)


def load_text(text: str) -> Boundaries:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("boundaries file is not a mapping")
    agent = data.get("agent") or {}
    acts_as = str(agent.get("acts_as", "agent")) if isinstance(agent, dict) else "agent"
    allowed = agent.get("allowed_ops") if isinstance(agent, dict) else None
    allowed_ops = (tuple(str(x) for x in allowed)
                   if isinstance(allowed, list) else None)
    agent_tenant = (str(agent.get("tenant")) if isinstance(agent, dict)
                    and agent.get("tenant") else None)
    untrusted = data.get("untrusted_fields") or []
    untrusted_fields = tuple(str(x) for x in untrusted) if isinstance(untrusted, list) else ()
    tenants = data.get("tenants") or {}
    tenant_param = (str(tenants.get("key")).split(".")[-1]
                    if isinstance(tenants, dict) and tenants.get("key") else None)
    return Boundaries(
        acts_as=acts_as, allowed_ops=allowed_ops,
        untrusted_fields=untrusted_fields, tenant_param=tenant_param,
        agent_tenant=agent_tenant,
    )


def load_path(path: str | Path) -> Boundaries:
    return load_text(Path(path).read_text(encoding="utf-8", errors="replace"))
