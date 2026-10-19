# ADR 0002: Authority as a first-class concept, via a boundaries file

Status: accepted (v0.1)
Date: 2026-10-20

## Context

An injected agent can be steered to call any tool it holds, so without
knowledge of the agent's authority the chain finder must assume every dangerous
tool is reachable from every untrusted entry. On a real spec that produces
thousands of low-signal findings. The distinctive value of this tool is
reasoning about authority, not just capability.

## Decision

Introduce an optional, declarative boundaries file that carries:

- the principal the agent acts as;
- the operations that principal may call (`allowed_ops`, glob patterns);
- fields that carry untrusted input (`untrusted_fields`);
- the path parameter that identifies a tenant (`tenants.key`).

When supplied, the finder scopes entries and terminals to what the agent can
actually reach, promotes that scoped reach from "generic guess" to a specific,
credible finding, and labels the boundary each chain crosses. When absent, the
finder falls back to unscoped reach and marks those findings generic.

## Consequences

- Findings become scoped and credible with a few lines of declaration, without
  the tool needing to execute anything.
- The same model extends to multi-agent delegation later (human to supervisor
  to worker) by recording authority per step.
- Quality now depends partly on the accuracy of the boundaries file; the report
  states when it is running unscoped.

## Alternatives considered

- Inferring scope from the spec's security schemes alone: too coarse; schemes
  rarely map to per-operation agent permissions.
- A full policy language: heavier than v0.1 needs; the glob list is enough to
  prove the idea and can grow later.
