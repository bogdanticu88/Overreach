# ADR 0001: Language and core approach

Status: proposed (Phase 0)
Date: 2026-10-19

## Context

We need to reach a working v0.1 quickly, at evening and weekend pace, while
keeping the reasoning core small and portable. The core must integrate with
model and agent libraries for inference and replay.

## Decision

- Strictly typed Python 3.12, type-checked with mypy in CI.
- The core (model, inference, taint, chains, breaker) stays small, with
  parsers, model providers and output formats as replaceable edges.
- Declarative rules over an in-memory graph with bounded search, rather than a
  full Datalog engine, until the rules outgrow it.

## Consequences

- Fastest route to v0.1 and the best library ecosystem for models and agents.
- A port to Go stays open because the core is small and dependency-light.
- If chain rules grow complex, revisit the engine choice (would be a new ADR).

## Alternatives considered

- Go (used for NIA): single binary, but slower to a first working engine and a
  thinner model/agent ecosystem.
- Soufflé / full Datalog: powerful, but heavier to build, run and read at v0.1.
