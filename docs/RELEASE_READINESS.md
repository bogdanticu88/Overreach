# v0.1 release readiness

Assessment after the security hardening, real-world evaluation, baseline
re-score, and boundaries-scoped evaluation. This is an engineering judgement, not
a marketing statement.

## Verdict: CONDITIONAL

Overreach is sound enough to release as a clearly-labelled pre-alpha: all quality
gates pass, the evidence model is honest, the one blocker found by evaluation was
fixed, and the tool demonstrably finds defensible composed attack paths on
unfamiliar APIs (the DigitalOcean MCP/credential family) while staying quiet on a
trivial control (Petstore: 0 findings). It is **not** an unconditional PASS: scoped
output still carries roughly 50% heuristic false positives under hand review, the
Mattermost recall reconstruction is approximate, and packaging work remains. It
is not a FAIL: nothing is broken and no claim is overstated.

## What the evidence shows

- Quality gates: ruff, mypy (strict), pytest (77), Bandit (0 issues), pip-audit
  (clean) — all green. See the exact commands and output in the task report.
- Evidence integrity: static analysis is always `hypothetical`; only exact-
  sequence scripted replay against the bundled reference API reaches `validated`,
  and the demo states replay is not proof an LLM would choose the steps.
- Real-world: parses Stripe (612 ops) and DigitalOcean (858 ops) in under a
  second, <60 MB, no duplicate or search-explosion issues.
- Baselines re-scored reproducibly: Gitea 17/20, Mattermost 13–15/20.
- Scoping works: a boundaries file removes all generic noise (Stripe 580→7, DO
  315→44); ~43–50% of the survivors are defensible hypotheticals by hand review.

## Remaining soundness items (correctness, not cosmetic)

These are precision limitations, each a nameable pattern with a known shape. None
is a crash or an overclaim; all are documented. They are candidate fixes **after**
v0.1, deliberately not changed at the gate:

1. Sink-writer heuristic fires on same-domain create+read pairs (e.g. create a
   toolbelt whose description is read back), producing data-theft false
   positives. Fix direction: require the writer and reader to be in different
   trust domains, or the read to be attacker-reachable.
2. `transfer`/`session` identity wording tags workspace file transfers as
   takeover. Fix direction: treat `transfer` as identity only on account /
   ownership objects.
3. Provider-bound URL fields (e.g. Stripe dispute evidence links) are treated as
   caller-named egress. Fix direction: distinguish a destination the caller names
   from a provider-fixed URL.
4. Trigger-terminal chains (push_mirrors-sync, hooks/{id}/tests, workflow
   dispatches) are recalled only at their setup op, counted as the three Gitea
   misses. Fix direction: model the trigger step, or credit the setup op.
5. Cross-file `$ref` specs are not resolved (must be bundled first) — a
   documented limitation, not a defect.

## Remaining packaging / documentation tasks (not soundness)

1. Version is still `0.0.1`; bump to `0.1.0` for the tag.
2. No CHANGELOG yet.
3. GitHub Actions are pinned to major tags (`@v4`), not commit SHAs — optional
   supply-chain hardening.
4. Boundaries files for Stripe/DO are illustrative; a short "writing a boundaries
   file" guide would help adopters.
5. Scoped-precision numbers are single-reviewer judgements; a second reviewer
   would strengthen them.

## Explicitly out of scope for v0.1

Modelling the roadmap threat classes (plugin install / code execution, config
tampering, cross-org federation, AI-recap injection, visibility downgrades) — see
`comparison.md`. These are new detection features, not release blockers.
