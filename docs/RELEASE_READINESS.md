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

### Independent review round 2 (resolved)

A second review of `v0.1.0-rc` at `ea1fbaa` returned a FAIL with two residual
bypasses and a stale-doc note. All fixed with regression tests:

- **High — DNS rebinding still bypassed the guard.** The guard validated the
  resolved IPs but then handed the sender the original URL, so a sender that
  re-resolved at connect time could reach loopback. Fixed: `GuardedHttpTransport`
  resolves once and passes the validated IPs to the sender (pinning contract
  `(url, payload, validated_ips)`). The contract requires the sender to connect
  to one of those IPs, set the URL hostname as Host / TLS SNI, not re-resolve,
  and re-apply the guard to any redirect target; delivery fails closed when no
  sender is supplied. Overreach ships no network sender — one must be supplied,
  which is the remaining integration-time condition. Regression tests drive a
  rebinding resolver (asserting the validated public address, not loopback) and
  the no-sender fail-closed path.
- **Medium — `load_path` could still read unbounded input** (a named pipe reports
  size 0; a file can grow/swap between stat and read). Fixed: open the fd
  non-blocking, reject non-regular files via `fstat`, and read with a hard
  `_MAX_BYTES+1` bound. Regression test rejects a FIFO.
- **Low — stale counts** (labelled-finding counts and the test total) and a
  `rescore.py` import-order lint. Fixed; CI lint now also covers `demo` and
  `docs`.

### Independent review round 1 (resolved)

A first review of `72d3cda` returned a FAIL
with one High, three Medium, and one Low finding, plus two process notes. All are
now fixed with regression tests (see the "review finding" commits):

- **High — SSRF guard accepted non-dotted-quad loopback** (e.g. decimal
  `2130706433`). Fixed: literal IPs recognised in every encoding; the guarded
  transport now resolves hostnames and refuses non-public answers.
- **Medium — spec size limit checked after full read.** Fixed: `load_path`
  rejects by on-disk size first.
- **Medium — chain cap bypassed + O(n²) adjacency.** Fixed: the cap is enforced
  in the cross-domain loop; adjacency is built from an inverted index.
- **Medium — benchmark artifacts stale / silent bad-input scoring.** Fixed:
  result JSONs regenerated, counts reconciled across docs, `rescore.py` warns and
  refuses to score an empty merge.
- **Low — hyphenated paths broke untrusted-field matching.** Fixed: segments
  normalised to one underscored noun.
- **Process — CI did not run on the RC branch; scan comment overclaimed gating.**
  Both fixed.

PR #1 merged `v0.1.0-rc` into `master`; GitHub Actions ran and all checks
(`test`, `scan`, `overreach`) passed, so the "CI running on GitHub" condition is
met. The pinning-contract condition now also has an in-repo, tested **reference
sender** (`overreach.reference_api.http_sender.pinning_http_sender`,
stdlib-only, opt-in, off the default path) that honours the contract — connect to
a validated IP, present the hostname for Host/TLS SNI, no re-resolve, fail closed
on redirects. An integrator can wire it or write their own; the default transport
still ships no sender and fails closed. It is not an unconditional PASS because
the single-reviewer precision judgement remains and a production integration
should still be reviewed; it is not a FAIL because nothing is broken and no claim
is overstated.

## What the evidence shows

- Quality gates: ruff, mypy (strict), pytest (104), Bandit (0 issues), pip-audit
  (clean) — all green. Package builds (sdist + wheel), `twine check` passes, and a
  clean-venv install runs `profile`/`scan`/`validate` and the flagship demo.
- Evidence integrity: static analysis is always `hypothetical`; only exact-
  sequence scripted replay against the bundled reference API reaches `validated`,
  and the demo states replay is not proof an LLM would choose the steps.
- Real-world: parses Stripe (612 ops) and DigitalOcean (858 ops) in under a
  second, <60 MB, no duplicate or search-explosion issues.
- Baselines re-scored reproducibly: Gitea 17/20, Mattermost 13–15/20.
- Scoping + precision fixes: a boundaries file removes all generic noise (Stripe
  469→3, DO 280→21), and the three false-positive classes are fixed, lifting
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
