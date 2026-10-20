# Changelog

All notable changes to Overreach are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[semantic versioning](https://semver.org/).

## [0.1.0] - unreleased (release candidate)

First tagged release candidate. Overreach reads an OpenAPI 3.x spec, infers what
each operation does, finds sequences of individually-legitimate operations an AI
agent could be manipulated into chaining into harm, ranks controls that would
interrupt them, and can validate chains against a bundled reference API.

### Implemented
- **Ingest.** OpenAPI 3.x in JSON or YAML. Safe by assumption: nothing from a
  spec is executed, external `$ref`s are never fetched, YAML is parsed in safe
  mode, references resolve lazily per operation with depth/node/cycle bounds, and
  size is capped. Composed schemas (`allOf`/`oneOf`/`anyOf`), nested objects and
  array items are walked; fields carry a `required` flag so composition-derived
  fields are not treated as always present.
- **Infer.** HTTP-verb and lexical rules assign effects (read, write, delete,
  send-out, change-identity, move-money, cost, irreversible), each with a
  provenance (`declared`/`inferred`/`observed`) and a confidence. Identity and
  money effects require a writing method; credential/key/OAuth-app creation and
  ownership transfer/rename (on ownable objects) are modelled as persistent
  access. An offline refiner prunes over-guesses; an optional model refiner is
  present but inert unless configured.
- **Taint.** Pairs free-text writers with readers on a specific resource noun to
  find where attacker-authored text reaches the agent.
- **Chains.** Bounded, deterministic, deduplicated search from untrusted entries
  to harmful terminals. Exfiltration sinks are restricted to communication-
  surface objects; an optional boundaries file scopes "any tool reachable" to the
  agent's real authority and enables cross-tenant detection.
- **Breaker.** Ranks control options, separating proposed coverage from
  conditional prevention (observed prevention requires a re-test).
- **Replay.** Validates a chain by executing its exact operation sequence against
  the in-process reference API with a unique canary; evidence is bound to the
  chain, never promoted by a different scripted attack.
- **Transport.** The reference API's webhook delivery is offline by default
  (records in memory, no socket). An opt-in `GuardedHttpTransport` refuses
  non-HTTP schemes and destinations that are, or resolve to, loopback/private
  addresses in any IP encoding, resolves a hostname once and pins the connection
  to the validated IPs, and fails closed without a sender. A stdlib-only
  reference pinning sender (`reference_api.http_sender`) is provided opt-in; the
  default path ships no network sender.
- **Reports.** JSON, SARIF 2.1.0, a self-contained HTML report, and a plain
  narrative. CLI: `profile`, `scan`, `validate`.
- **Quality.** ruff, mypy (strict), pytest (104 tests), Bandit and a runtime
  dependency audit, all in CI; GitHub Actions pinned to commit SHAs.

### Evidence model
`hypothetical` (from the spec) → `simulated` (reserved) → `validated` (the exact
sequence executed against an authorised implementation and the canary observed
leaving). `validated` means the API permits the sequence; it is **not** proof an
LLM would independently choose it.

### Evaluated
- Real-world specs: Stripe (612 ops), DigitalOcean (858 ops), a Petstore control
  (0 findings). See `docs/baselines/realworld_eval.md`.
- Independent baselines re-scored reproducibly: Gitea 17/20, Mattermost 13–15/20
  (`docs/baselines/baseline_rescore.md`).
- Boundaries-scoped: Stripe 469→3 findings (3/3 defensible), DigitalOcean 246→21
  (20/21 defensible) (`docs/baselines/scoped_eval.md`).

### Known limitations
- Unscoped output on large specs is dominated by generic "any tool reachable"
  emission; supply a boundaries file for signal.
- Multi-file specs must be bundled before scanning (external `$ref`s are not
  fetched).
- Not yet modelled (roadmap, `docs/baselines/comparison.md`): code-execution /
  plugin-install, config tampering, cross-org federation, AI-recap injection,
  visibility downgrades, and trigger-step terminals (recalled at their setup op).
- `scan` exit codes gate on impact, not evidence level.
- Findings are reachability analysis at `hypothetical` evidence unless validated
  against an authorised instance; they are leads, not confirmed vulnerabilities.
