# Overreach — Security & Quality Audit

Scope: full repository review per the hardening assignment. Every source file
listed below was read in full before any finding was written. Findings are
ranked by severity. Each carries file:line, impact, and disposition.

## Baseline

- Commit at audit start: `0ad46f53a229da76456c9a2037613d5be0f3300b`
- Python: 3.12. Package: `overreach`, entry point `overreach` → `overreach.cli:main`.
- Source size: ~2,100 LOC across 15 modules (`find src -name '*.py' | xargs wc -l`).
- Tests at audit start: **34 passed**. After this pass: **77 passed in ~1.1s**.
- `mypy src/overreach` (strict): **clean, 15 files**.
- `ruff check src tests`: 13 findings at start → **clean** after a documented
  `[tool.ruff.lint]` config (see F-11).
- `pip-audit`: no advisories against the project's declared dependency
  (`PyYAML`). Advisories reported for `pypdf`, `setuptools`, `wheel` are the
  container's build/toolchain packages, not Overreach dependencies.

### Files inspected
`src/overreach/`: `__init__.py`, `model.py`, `cli.py`, `ingest/__init__.py`,
`infer/__init__.py`, `infer/refine.py`, `taint/__init__.py`,
`chains/__init__.py`, `boundaries/__init__.py`, `breaker/__init__.py`,
`replay/__init__.py`, `report/__init__.py`, `reference_api/__init__.py`,
`reference_api/app.py`, `reference_api/transport.py` (new). Plus all tests,
`pyproject.toml`, workflows, and `docs/`, `examples/`.

## Architecture & data flow

```
spec (OpenAPI JSON/YAML)
  └─ ingest        parse + bounded $ref resolve → Api(Operation[], Field[])
       └─ infer    HTTP-verb + lexical rules → Effect[] (provenance=INFERRED, confidence<1)
            └─ refine   OfflineRefiner prunes over-guesses / adds COST; LLMRefiner inert by default
       └─ taint    write→read links on the *specific* resource noun → entry points (untrusted text)
  └─ boundaries    optional authority file: acts_as, allowed_ops, tenant_param, agent_tenant
  └─ chains        graph search entry→terminal, bounded depth; HYPOTHETICAL only
  └─ breaker       weighted greedy set-cover → ranked control Options
  └─ report        JSON / SARIF 2.1.0 / HTML / narrative
  └─ replay        execute a chain's EXACT op sequence vs the reference API → VALIDATED iff canary observed
```

Evidence ladder is modelled in the type system: `Evidence.{HYPOTHETICAL,
SIMULATED, VALIDATED}` and `Provenance.{DECLARED, INFERRED, OBSERVED}`. The
design invariant — static analysis is always HYPOTHETICAL and only replay can
raise it — holds in `chains` (hard-codes HYPOTHETICAL) and is the subject of
finding F-2.

---

## Findings

### F-1 — SSRF / exfiltration primitive in the reference API  ·  Severity: HIGH  ·  **FIXED**
`reference_api/app.py` (was ~line 150, `trigger_push`).

Before: `trigger_push` called `httpx.post(url, json=payload, timeout=2.0)` for
any caller-registered webhook URL, guarded only by a `sink://` string check and
a `# pragma: no cover - real delivery not used in tests` comment. A caller could
register `http://169.254.169.254/...` or any internal address; a push would make
a real outbound request from wherever the demo ran. Requirement §3A violated
("no reliance on comments claiming a sandbox is safe").

Fix: new `reference_api/transport.py`.
- `Transport` Protocol; `CaptureTransport` (default) records payloads in memory
  and **opens no socket, ever** — `app.py:32` wires it at module load.
- `is_blocked_destination(url)` (transport.py:46) rejects non-http(s) schemes,
  missing host, `localhost` variants, and literal IPs that are private /
  loopback / link-local / reserved / multicast / unspecified.
- `GuardedHttpTransport` (opt-in, injected sender) refuses blocked destinations
  before calling the sender; never wired by default.
- `httpx` import removed from `app.py`; `/_sink` endpoint removed.

Tests: `tests/test_transport.py` — 14 blocked-destination cases (external,
loopback, private, link-local, metadata IP, malformed, non-HTTP), 2 allowed,
plus "default transport never sends" and "guarded transport refuses unsafe /
sends only to public". **Regression coverage added per §3A.**

### F-2 — Replay could validate a chain from an unrelated scripted attack  ·  Severity: HIGH  ·  **FIXED**
`replay/__init__.py` (was: dispatcher matched scenarios by substring, e.g.
`any("hooks" in k for k in op_keys)`).

Before: validation selected a scripted scenario by broad operation-name
matching. A chain that merely *mentioned* a hook-like operation could be handed
the exfiltration scenario's success and promoted to VALIDATED — a false positive,
exactly the evidence-integrity failure called out in §3B / §12D.

Fix: scenarios are keyed by the **exact operation-key tuple** of the chain
(`_SCENARIOS: dict[tuple[str,...], Scenario]`, replay/__init__.py:153).
`validate_chain` (line 160) looks up `tuple(s.op_key for s in chain.steps)`;
no exact match → stays HYPOTHETICAL with detail "no replay scenario matches this
operation sequence exactly". Each run calls `reset_state()` for isolation and
plants a unique canary (`secrets.token_hex`). The result carries a structured
`ReplayEvidence` record: `ops`, `identity`, `canary`, `requests`
(method/path/params), `observed_effect`, `leaked`. VALIDATED **iff** the canary
is actually observed leaving (capture log for exfil, response body for
cross-tenant, notification for takeover).

Tests: `tests/test_replay_binding.py` — exact-sequence validates & records;
unrelated sequence (`GET/DELETE /admin/hooks…`) is **not** borrowed → HYPOTHETICAL,
`record is None`; partial prefix not matched; each run uses a unique canary.
Updated `tests/attacks/test_reference_api.py` and `tests/test_boundaries.py` to
assert the bound record. **Adversarial false-positive tests added per §3B.**

### F-3 — Breaker conflated *proposed coverage* with *verified prevention*  ·  Severity: MEDIUM  ·  **FIXED**
`breaker/__init__.py` (was: `_breaks()` + `Option.chains_broken`).

Before: `_breaks` returned True whenever a control's target merely appeared in a
chain, and `Option.chains_broken` counted those as broken — so `require_approval`
and `mark_field_untrusted` were reported as if they prevented the path. §3C
forbids treating human approval or untrusted-input labels as automatic
prevention.

Fix: controls are now classified `enforces` (technical block) vs mitigation.
`_covers` (proposed positioning) is separated from `_prevents` (enforcing +
precondition met). `Option` reports `chains_prevented` **and** `chains_covered`
separately, plus `verified=False` (only a replay retest may set it True).
Preconditions are modelled: `remove_permission` prevents a chain only if it
removes an operation the chain depends on; `egress_allowlist` prevents only a
data-theft chain whose terminal actually makes a caller-named outbound request
(`Chain.terminal_exit`, added in `chains/__init__.py`) — so it is no longer
mis-offered for cross-tenant reads or reader-visible-sink writes. Approval and
untrusted-field are offered as mitigations that raise coverage, never
prevention. Ranking is deterministic: greedy with a stable control-identity
tie-break, and a final identity tuple in the sort key.

Tests: `tests/test_breaker.py` — prevention uses only enforcing controls;
untrusted-label/approval never count as prevention or enforcement; egress
allowlist offered only for outbound-exit data theft and not for takeover or
non-outbound exfil; nothing is `verified` without a retest; ranking is
byte-stable across repeated runs.

### F-4 — OpenAPI ingest missed composed/nested schemas; ref-expansion not work-bounded  ·  Severity: MEDIUM  ·  **FIXED**
`ingest/__init__.py` `_collect_fields`, `_resolve`, new `_walk_schema`.

Before: `_collect_fields` read only the top-level `properties` of a request body
(missed `allOf`/`oneOf`/`anyOf`, nested objects, array `items` → false
negatives); `_resolve` bounded depth but not total expansion work; warnings were
limited to "no operations found".

Fix:
1. New `_walk_schema` descends nested objects, array `items`, and `allOf` /
   `oneOf` / `anyOf`, bounded by `_MAX_SCHEMA_DEPTH` and `_MAX_SCHEMA_NODES`, so
   exit/free-text fields buried in composed schemas are found.
2. `_resolve` now carries a `_Ctx` with a total-node budget
   (`_MAX_RESOLVE_NODES`) on top of the depth bound, capping repeated-reference
   amplification regardless of shape; cycles still terminate at the depth bound.
3. Warnings are emitted (deduped) for external refs (never fetched), unresolved
   internal refs, ambiguous `oneOf`/`anyOf`, and any depth/node truncation.
   Malformed YAML/JSON now raises a clear `IngestError` rather than propagating a
   parser exception.

Tests: `tests/test_ingest_hostile.py` (14) — malformed input, non-mapping paths,
oversized spec, garbage operations, external ref (not fetched + warned),
self-referential cycle (terminates, still finds the nested exit field),
unresolved ref, repeated-reference fan-out (bounded, returns), nested-object and
array-item exit fields, `allOf` merge, `oneOf` branch handling + warning, and
deep-nesting truncation. **Hostile fixtures delivered per §3D.**

### F-5 — Demo output mixed "hypothetical" and "VALIDATED" on the same finding  ·  Severity: LOW  ·  **FIXED**
`cli.py` `_validate_demo`.

The demo now prints a header stating that static analysis grades everything
hypothetical and that a "validated" mark means scripted, deterministic replay
observed the effect — explicitly **not** evidence a live LLM would choose the
steps. Each finding reads `static: hypothetical -> replay: VALIDATED (scripted)`
with a `replay proof:` line, so the static-vs-replay distinction is unmistakable
per §5.

### F-6 — Taint free-text hints include `name`/`title`, inflating entries  ·  Severity: LOW  ·  **OPEN**
`taint/__init__.py:17` `_FREE_TEXT_HINTS`.

`name`, `title`, `subject` are treated as free-text injection carriers. On many
APIs these are short, validated labels, not markdown bodies an attacker seeds
with agent instructions. This can create entry points that inflate generic
findings on unfamiliar specs (relevant to the §7 false-positive measurement).
Disposition: measure on real specs (§7) before tuning; candidate to gate behind
boundaries' `untrusted_fields`.

### F-7 — `uncertain_operations` threshold is reported but unused by the pipeline  ·  Severity: INFO
`infer/__init__.py:111`. Used only by `profile`'s stats, not to drive the
(inert) `LLMRefiner`. Correct for v0.1 (model pass unshipped); noted so docs
don't imply a model runs. Matches §11 "prefer deterministic reasoning".

### F-8 — `--fail-on` maps severity by impact heuristic only  ·  Severity: INFO
`cli.py:164`. `worst` is derived from `impact` (5→error, 4→warning, else note),
not from evidence level. Reasonable for v0.1; document that exit code reflects
impact, not validation status, so CI users aren't surprised.

### F-9 — SARIF `informationUri` lower-cased the repo slug  ·  Severity: INFO  ·  **FIXED**
`report/__init__.py` now emits `github.com/bogdanticu88/OverReach`.

### F-10 — HTML report escaping is correct  ·  Severity: INFO (verified, no action)
`report/__init__.py:100` `_esc` is applied to every spec-derived string rendered
into HTML (narrative, op keys, boundaries, control descriptions, title).
Enum-valued fields (`outcome.value`, badge level) are a fixed vocabulary.
No XSS vector found. Recorded because §6 calls out HTML reporting.

### F-11 — Lint baseline  ·  Severity: INFO  ·  **FIXED**
Added `[tool.ruff]` / `[tool.ruff.lint]` to `pyproject.toml`: enforce E/F/I/UP/B
at a 100-char line length, with justified ignores for `B008` (FastAPI
`Depends()` default) and `UP042` (str+Enum kept so `str()` output we format on
does not change). Dead imports removed; two long lines wrapped. `ruff check src
tests` is clean.

### F-12 — `networkx` declared but unused  ·  Severity: LOW  ·  **FIXED**
`pyproject.toml`. `networkx>=3.0` was a declared runtime dependency but is
imported nowhere (the chain finder uses a hand-rolled graph). Removed; the only
runtime dependency is now `PyYAML`. `fastapi`/`httpx` remain in the `demo`/`dev`
extras (httpx backs Starlette's in-process TestClient). Addresses §6/§10
"no unnecessary dependencies".

---

## Deliverable D — Evidence-integrity assessment

Can Overreach label a hypothetical path as validated incorrectly?

- **Before this pass: yes.** The substring dispatcher (F-2) could hand one
  chain's scripted success to a different chain.
- **After this pass: not via the known vector.** Validation is bound to the
  chain's exact operation-key tuple; a non-matching or partial sequence stays
  HYPOTHETICAL and carries no record. VALIDATED requires the unique canary to be
  observed in the real effect channel. Established by
  `tests/test_replay_binding.py` (unrelated/partial sequences, unique canary per
  run) and the updated attack/boundary tests (bound `ReplayEvidence` record).
- **Residual limits:** validation only covers the three bundled reference-API
  scenarios; any other chain is correctly left HYPOTHETICAL rather than guessed.
  "Validated" means "the scripted sequence produced the effect against the
  in-process reference API" — **not** that a live LLM would choose the sequence,
  and not a claim about any third-party system.

## Deliverable F — Release readiness

**CONDITIONAL.** Fixed in this pass: F-1, F-2, F-3, F-4, F-5, F-9, F-11, F-12.
Remaining before a v0.1 tag:
1. §7 real-world run on ≥2 public specs with recorded metrics + limitations
   (the ingest fix in F-4 unblocks this; the run itself is still to do).
2. bandit run recorded (§8); pip-audit done (clean against declared deps).
3. README evidence-levels + limitations section aligned to actual behavior (§9),
   and a CHANGELOG + v0.1 version bump (§10).
4. Security CI: add bandit + pip-audit to the workflow.
Non-blockers: F-6 (taint `name`/`title` hints — measure in §7 first), F-8
(`--fail-on` reflects impact, not evidence — document).

## Deliverable G — Top 5 next improvements (after this hardening)
1. Breaker: coverage-vs-prevention split + replay-backed "verified" retest (F-3).
2. Ingest: recursive schema walk (allOf/oneOf/anyOf, nested, arrays) + node
   budget + warnings + hostile fixtures (F-4).
3. §7 external-spec benchmark harness with recorded false-positive/runtime
   metrics and a `docs/` limitations writeup.
4. Per-finding "unverified assumptions" field surfaced in narrative/SARIF (§4 Q6).
5. Security CI: add bandit + pip-audit to the workflow; pin dependencies.
