# v0.1.0 release readiness

Assessment after the security hardening, real-world evaluation, baseline
re-score, boundaries-scoped evaluation, the three false-positive fixes, v0.1.0
packaging, the flagship demo, and the reviewer package. This is an engineering
judgement, not a marketing statement.

## Verdict: CONDITIONAL (release candidate)

Overreach 0.1.0 is ready to ship as a clearly-labelled alpha **release
candidate**. All quality gates pass, the evidence model is honest, the blockers
and false-positive classes found by evaluation are fixed, the package builds and
installs cleanly, and the tool demonstrably finds defensible composed attack
paths on unfamiliar APIs (the DigitalOcean MCP/credential family) while staying
quiet on a trivial control (Petstore: 0 findings).

The remaining condition is **independent review** (the reviewer package exists
for exactly this) plus the documented non-blocking items below. It is not an
unconditional PASS because scoped precision rests on a single reviewer's
judgement and the roadmap threat classes are unmodelled; it is not a FAIL because
nothing is broken and no claim is overstated.

## What the evidence shows

- Quality gates: ruff, mypy (strict), pytest (85), Bandit (0 issues), pip-audit
  (clean) — all green. Package builds (sdist + wheel), `twine check` passes, and a
  clean-venv install runs `profile`/`scan`/`validate` and the flagship demo.
- Evidence integrity: static analysis is always `hypothetical`; only exact-
  sequence scripted replay against the bundled reference API reaches `validated`,
  and the demo states replay is not proof an LLM would choose the steps.
- Real-world: parses Stripe (612 ops) and DigitalOcean (858 ops) in under a
  second, <60 MB, no duplicate or search-explosion issues.
- Baselines re-scored reproducibly: Gitea 17/20, Mattermost 13–15/20.
- Scoping + precision fixes: a boundaries file removes all generic noise (Stripe
  469→3, DO 246→21), and the three false-positive classes are fixed, lifting
  scoped precision to Stripe 3/3 and DigitalOcean 20/21 by hand review.

## Soundness items

The three precision defects from the scoped evaluation are **fixed** (see
`test_precision.py` and `scoped_eval.md`): scoped precision rose to Stripe 3/3
and DigitalOcean 20/21.

- ~~Sink-writer heuristic fires on same-domain create+read pairs.~~ Fixed:
  exfiltration sinks are restricted to communication-surface objects.
- ~~`transfer` wording tags workspace transfers as takeover.~~ Fixed: gated on an
  ownable object.
- ~~Provider-bound URLs / subject emails treated as egress.~~ Fixed: excluded from
  egress detection.

Remaining, documented, not release-blocking:

1. Trigger-terminal chains (push_mirrors-sync, hooks/{id}/tests, workflow
   dispatches) are recalled only at their setup op — the three Gitea misses.
   Fix direction: model the trigger step, or credit the setup op.
2. One borderline DigitalOcean scoped finding (`-> POST
   /v2/agents/sessions/policy/validate`) remains weak; left honest rather than
   force-fixed.
3. Cross-file `$ref` specs are not resolved (must be bundled first) — a
   documented limitation, not a defect.

## Packaging / documentation — done in this RC

- Version bumped to `0.1.0`, development-status classifier to Alpha.
- `CHANGELOG.md` added (functionality, evidence model, evaluation, limitations).
- GitHub Actions pinned to reviewed commit SHAs in both workflows.
- `docs/boundaries_guide.md` added; README points at it and the changelog.
- Package builds (sdist + wheel), `twine check` passes, clean-venv install runs
  every README command.
- Flagship demo (`demo/flagship_demo.py`) and reviewer package
  (`docs/REVIEWER_PACKAGE.md`) added.

## Remaining before a final (non-RC) release

1. Independent security review (reviewer package is ready for it).
2. Scoped-precision numbers are single-reviewer judgements; a second reviewer
   would strengthen them.
3. Trigger-step terminal recall (the three Gitea misses) if higher recall is
   wanted.
4. Transient Starlette→httpx deprecation warning from the demo extra (cosmetic).

## Explicitly out of scope for v0.1

Modelling the roadmap threat classes (plugin install / code execution, config
tampering, cross-org federation, AI-recap injection, visibility downgrades) — see
`comparison.md`. These are new detection features, not release blockers.
