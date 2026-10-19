# ADR 0003: Two-pass effect inference with a pluggable refiner

Status: accepted (v0.1)
Date: 2026-10-20

## Context

Rule-based effect inference is fast and deterministic but over-guesses from
lexical cues: "transfer a repo" or "order of results" wrongly read as money
movement. The design calls for a model pass on uncertain operations, but the
tool must stay useful and testable offline, and a model must never silently
outrank a rule.

## Decision

Inference runs in two passes. Rules first, then a refiner:

- `OfflineRefiner` (default): deterministic, no network. Prunes money effects
  with no commerce context, flags unbounded list reads as a cost signal, and
  drops or boosts identity guesses by how specific the object is.
- `LLMRefiner` (optional): sends only uncertain operations to a model, validates
  the output against a schema, keeps provenance `inferred`, and caps confidence
  so a model never outranks a rule. Inert until a provider is configured.

`get_refiner()` chooses; `infer_api(..., refine=False)` turns it off.

## Consequences

- Measured precision gain with no model: money false positives fell from 15 to
  9 on Gitea and 15 to 3 on Mattermost.
- A real model provider can be added behind the same interface and measured
  against the spike specs before it is trusted.
- COST is recorded as an effect for profiling but is not a chain terminal; a
  single unbounded list is a robustness issue, not an injection chain.

## Alternatives considered

- Model-only inference: slower, costlier, non-deterministic, and untestable
  offline.
- Dropping lexical money cues entirely: loses real signal on commerce APIs.
