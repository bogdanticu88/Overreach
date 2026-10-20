<p align="center">
  <img src="assets/overreach-logo.png" alt="Overreach" width="520">
</p>

<p align="center"><strong>Find dangerous sequences of legitimate API calls that AI agents could be manipulated into executing.</strong></p>

<p align="center">
  <a href="https://github.com/bogdanticu88/OverReach/actions/workflows/ci.yml"><img src="https://github.com/bogdanticu88/OverReach/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0">
  <img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/evidence-hypothetical%20%E2%86%92%20validated-6b7cff.svg" alt="Evidence levels">
  <img src="https://img.shields.io/badge/status-pre--alpha-orange.svg" alt="Status: pre-alpha">
</p>

# Overreach

Overreach reads an API specification, works out the ways an AI agent using it
could be steered into harm by chaining together individually legitimate calls,
says how strong the evidence for each chain is, and ranks the smallest set of
controls that would break them.

> Status: pre-alpha, and honest about it. The full pipeline runs end to end on a
> bundled reference API, and it has been run against large real specifications
> (`docs/baselines/realworld_eval.md`). It over-reports on unscoped specs; its
> signal depends on a boundaries file. The misses and false-positive patterns are
> written down, not hidden.

## The problem

APIs get reviewed one operation at a time: is this endpoint authenticated, is
that one destructive, does this one leak data. Agents do not use APIs one
operation at a time. They chain calls, they read text other people wrote, and
they act with whatever identity they were handed.

So an API can pass every per-endpoint check and still let a manipulated agent do
real damage in a few steps that each look harmless. An attacker writes a line
into an issue comment. The agent reads it while doing an ordinary task. Following
that text, the agent registers a webhook, or reads a file from another tenant, or
changes an account's email. No single call is a vulnerability. The sequence is.

Overreach looks for those sequences, from the attacker's text to the harmful
outcome, and treats the agent as what it is: a capable worker with no judgement
about what is off limits.

## What makes it different from a conventional API scanner

A DAST tool or a per-endpoint linter asks "is this one operation broken?".
Overreach asks "what harmful **sequence** do these operations allow an agent to
be talked into?". Three things follow from that, which endpoint-level tools do
not combine:

**It is honest about evidence.** A chain found in a spec is `hypothetical`. A
chain whose exact operation sequence was executed against a real implementation,
with a planted canary observed leaving, is `validated`. The levels are enforced
in the type system, so static analysis cannot silently promote itself.

**It reasons about authority, not just capability.** An optional boundaries file
says what the agent may do, which fields carry untrusted input, and which path
parameter marks a tenant. With it, Overreach scopes "any tool reachable" down to
what the agent can actually touch, and flags when a chain crosses a tenant or
ownership boundary. Without it, Overreach assumes any held tool is reachable and
says so (those findings are labelled `generic`).

**It hands back fixes, and separates coverage from prevention.** The Breaker
ranks a short list of controls that cut the chains, and distinguishes a control
that is merely *positioned* on a chain from one that would *prevent* it, and
conditional prevention (if the control is enforced) from observed prevention
(demonstrated by re-test). It never counts "require human approval" or "mark this
field untrusted" as prevention.

## Quick start (under five minutes)

```bash
git clone https://github.com/bogdanticu88/OverReach && cd OverReach
pip install -e ".[demo]"     # runtime is just PyYAML; [demo] adds the reference API
overreach validate           # run the end-to-end demo described below
```

To scan your own spec you need only the runtime dependency:

```bash
pip install -e .
overreach scan path/to/openapi.json --boundaries path/to/boundaries.yaml
```

## A reproducible multi-step attack path

For the full story end to end — attacker input, agent authority, the permitted
call sequence, the boundary crossed, the leaked canary, a proposed control, and a
rerun showing the control actually prevents it — run `python demo/flagship_demo.py`
(see `demo/README.md`). It is offline and deterministic.

`overreach validate` is the quick version. It scans a bundled reference API (a
small code host written to score well on agent-readiness linters), then
**executes** each discovered chain against an in-process copy with a unique canary
and watches whether the canary leaves:

```
Reference API: 3 finding(s) (scoped by the bundled boundaries file).
Static analysis grades every finding 'hypothetical'. The replay harness then executes each
chain's exact operation sequence against the in-process reference API with a unique canary.
A 'validated' mark means that scripted, deterministic replay observed the effect; it is NOT
evidence that a live LLM would independently choose these steps.

[df301d8e0d43] data_theft  static: hypothetical -> replay: VALIDATED (scripted)
    An attacker writes text into body that the agent later reads at
    GET /repos/{owner}/{repo}/issues/{issue_number}/comments. Following that text, the agent
    can exfiltrate data by reaching POST /repos/{owner}/{repo}/hooks in 2 step(s), each
    individually permitted. Boundary crossed: untrusted text drives a privileged action.
    replay proof: private file contents delivered to attacker destination https://attacker.example/... (canary CANARY-...)

[a3af9754ae4d] data_theft  static: hypothetical -> replay: VALIDATED (scripted)
    ... the agent reaches GET /repos/{owner}/{repo}/contents/{path} ...
    Boundary crossed: crosses tenant boundary: no ownership check for 'owner'.
    replay proof: read another tenant's private file; the tenant parameter is not checked ...
```

A clean linter score next to a scripted, two-step breach is the point. The
scripted replay proves the **API permits** the sequence; it is not a claim that a
live model would independently choose it.

## Commands

```bash
overreach profile <spec>                     # what the tool sees in a spec
overreach scan <spec>                        # find chains and ranked fixes
overreach scan <spec> --boundaries <file>    # scope findings to the agent's authority
overreach scan <spec> --sarif out.sarif      # SARIF 2.1.0 for GitHub code scanning
overreach scan <spec> --html report.html     # a shareable HTML report
overreach scan <spec> --fail-on error        # non-zero exit when an error-level finding exists
overreach validate                           # run the bundled reference demo end to end
```

Exit codes: `0` success, `1` when `--fail-on` is set and a finding at or above the
threshold exists (the threshold is by **impact**, not evidence level), `2` on a
usage error. Output is deterministic for a given spec and boundaries file.

Writing a boundaries file is covered in `docs/boundaries_guide.md`; release notes
and limitations are in `CHANGELOG.md`.

## How it works

Five stages, each useful on its own, each feeding the next.

1. **Ingest.** Parse an OpenAPI 3.x spec safely. Nothing from the spec is ever
   executed, external `$ref` targets are never fetched, and references are
   resolved lazily with depth, node and cycle bounds. Multi-file specs must be
   bundled first (Overreach does not fetch sibling files).
2. **Infer.** Work out what each operation really does (reads, writes, sends out,
   changes identity, destroys, costs) and label fields. Every effect carries a
   provenance (`declared`, `inferred`, `observed`) and a confidence.
3. **Find chains.** Pair the places where untrusted free text enters with the
   operations that cause harm, and search the paths between them, bounded and
   deduplicated.
4. **Break them.** Compute the ranked control options that cut the chains,
   separating proposed coverage from (conditional) prevention.
5. **Prove them.** Against a real implementation, run the chain's exact sequence
   with canary data and watch whether the canary leaves. Only then `validated`.

## Evidence levels

| Level | Meaning | What it may claim |
| --- | --- | --- |
| `hypothetical` | A chain inferred from the specification | A lead worth investigating |
| `simulated` | Succeeded against a generated model of the API | Plausible; the real API may enforce checks the spec does not show |
| `validated` | The exact sequence was executed against an authorised implementation and the canary was observed leaving | That implementation permits the sequence |

`validated` means the **API permits** the sequence under scripted replay. It is
not proof that an LLM would choose those steps, and a chain from a third-party
spec stays `hypothetical` until validated against an authorised instance.

## Proposed coverage vs verified prevention

The Breaker reports two different things, and does not blur them:

- **Coverage** (`chains_covered`): a control is positioned on the chain. Marking a
  field untrusted or requiring human approval covers a chain; it does not, on its
  own, prevent it.
- **Conditional prevention** (`chains_prevented`): an enforcing control (an egress
  allowlist on an outbound exit, or removing a permission the chain depends on)
  would block the chain **if the enforcement assumption holds**. An egress
  allowlist is only offered where the terminal actually makes a caller-named
  outbound request.
- **Observed prevention** (`observed_prevention`): only true after the control is
  enforced and the chain is re-tested and no longer succeeds. Overreach does not
  claim this from static analysis.

## What Overreach cannot determine from OpenAPI alone

- Whether one agent identity actually holds both the read and the write
  permission in a chain. It assumes this; it cannot confirm it from a spec.
- Whether a tenant parameter is ownership-checked. Cross-tenant findings require
  an explicit boundaries file (`tenant_param`, `agent_tenant`) and remain
  `hypothetical`.
- Whether text read at one step actually reaches the destination at another. Data
  flow is paired on the shared resource noun, which is a heuristic.
- Whether a field is present in a given request. A field extracted from an
  `oneOf`/`anyOf` branch is only *possibly* present; such fields are marked
  `required=False` and the spec gets a warning. Parser coverage is not semantic
  presence.

## Known limitations and expected false positives

Measured on Stripe, DigitalOcean and a Petstore control
(`docs/baselines/realworld_eval.md`):

- **Unscoped specs over-report.** Without a boundaries file, the output is
  dominated by `generic` "any tool reachable" emission and by lexical money-word
  terminals. Read these as leads, and supply a boundaries file for signal.
- **Free-text heuristics.** Entry points are seeded only from strong free-text
  fields (body, comment, description, message, content, note, text, bio);
  `name`/`title`/`subject` were deliberately dropped because on real specs they
  matched data fields far more than injection carriers.
- **Multi-file specs** must be bundled (e.g. with redocly or swagger-cli) before
  scanning.
- On the Petstore control, Overreach correctly reports **nothing**. On
  DigitalOcean's agent/action-gateway surface it surfaced a defensible composed
  path a per-endpoint scanner would miss. That contrast is the point.

## How good is it

Two reviewers with no knowledge of the tool each hand-wrote the attack chains
they would expect in two real products, from the operation list alone. The finder
is scored against those independent baselines with a committed, reproducible
scorer (`docs/baselines/rescore.py`, `baseline_rescore.md`): Gitea recall is
**17/20** (the three misses are trigger chains whose setup op is flagged) and
Mattermost is **13–15/20** depending on terminal-map strictness. The real-world
evaluation (`realworld_eval.md`) records behaviour on unfamiliar large specs, and
the boundaries-scoped evaluation (`scoped_eval.md`) shows scoping cutting Stripe
from 469 to 3 findings and DigitalOcean from 246 to 21, with every scoped finding
hand-labelled (Stripe 3/3 and DigitalOcean 20/21 are defensible hypotheticals
after the precision fixes). All three live under `docs/baselines/`.

## Safety

Overreach is built to be pointed at hostile input. It never executes or fetches
anything from a spec, parses YAML in safe mode only, bounds size, reference depth
and per-operation work, and keeps any execution to an authorised target via the
offline-safe reference transport. CI runs ruff, mypy (strict), pytest, Bandit and
a dependency audit. See `SECURITY.md`.

## Roadmap

Known gaps, in rough priority: code-execution and plugin-install effects,
configuration tampering, visibility and ownership changes, cross-org federation
sinks, boundaries files for the real-world specs to measure scoped precision, and
a model pass for the effects the rules are unsure about. The honest backlog lives
in `docs/baselines/comparison.md` and `docs/AUDIT.md`.

## Contributing

See `CONTRIBUTING.md`. New attack patterns come with a test, ruff/mypy/pytest stay
green, and nothing ever executes input.

## License

Overreach is free software under the GNU AGPL-3.0 (see `LICENSE`). A separate
commercial edition and hosted service are also offered; `CONTRIBUTING.md`
explains how contributions are licensed so both remain possible.

Copyright (C) 2026 Mihai-Bogdan Ticu.
