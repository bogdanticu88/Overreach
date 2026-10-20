# Real-world evaluation on unfamiliar OpenAPI specifications

This records how Overreach behaves on public APIs it was not built around. The
goal is not a high finding count. It is to establish whether Overreach can
surface a *defensible* composed attack path that a conventional, single-endpoint
scanner would overlook, and to be honest about where it over-reports.

## Methodology

- Pipeline run per spec: `ingest -> infer (rule + offline refine) -> find_chains`,
  with **no boundaries file** (the unfamiliar-API case: no declared authority).
  Harness: `scratchpad/eval_harness.py`, run as `python -I` in an isolated
  process per spec.
- Metrics: operations parsed, fields extracted, exit fields, chains by outcome
  and evidence level, specific vs generic, duplicate chain ids, whether the
  `_MAX_CHAINS` cap was hit, parser warnings, wall-clock per stage, and peak RSS
  (`resource.getrusage(RUSAGE_SELF).ru_maxrss`).
- Manual review: the highest-impact findings were read by hand and judged for
  plausibility under their stated assumptions. No finding here is claimed to be
  an exploitable vulnerability; these are reachability results over a spec.
- Specs are not committed (size, licensing). They are reproducible from the
  sources and commits below. Overreach version: the commit this file is added in.

### Sources (reproducible)

| Spec | Source | Commit | File | SHA-256 (input) |
|---|---|---|---|---|
| Stripe API | github.com/stripe/openapi | `f3799ad` | `openapi/spec3.json` | `7cff4cc46d065410…` |
| DigitalOcean API | github.com/digitalocean/openapi | `5a1d9c7` | `specification/DigitalOcean-public.v2.yaml`, bundled with `@redocly/cli@1.25.11` | `fbb4a1293861afa3…` (bundled) |
| Swagger Petstore (control) | github.com/OAI/OpenAPI-Specification | `4f86429` | `_archive_/schemas/v3.0/pass/petstore-expanded.yaml` | `b1633b6309c065c4…` |

DigitalOcean's published root uses 867 external file `$ref`s. Overreach never
fetches external refs (by design), so the multi-file root had to be bundled into
one document first. **Limitation:** Overreach does not resolve cross-file refs;
multi-file specs must be bundled (e.g. with redocly or swagger-cli) before
scanning. This is recorded as expected behaviour, not a defect.

## Results (no boundaries supplied)

| Spec | Ops parsed | Fields | Chains | specific / generic | Dup ids | Cap hit | Warnings | Total time | Peak RSS |
|---|---|---|---|---|---|---|---|---|---|
| Petstore | 4 | 6 | **0** | 0 / 0 | 0 | no | 0 | 0.02 s | 18 MB |
| Stripe | 612 | 8,732 | 469 | 281 / 188 | 0 | no | 1 | ~0.4 s | 59 MB |
| DigitalOcean | 858 | 4,160 | 280 | 97 / 183 | 0 | no | 1 | ~0.3 s | 45 MB |

> These counts are current after the correctness fixes made during hardening and
> independent review: credential/key and ownership-transfer effect modelling,
> gating identity/money effects to writing methods, restricting the exfil sink to
> communication surfaces, excluding provider/subject URLs and emails from egress,
> and normalising hyphenated path segments (which raised DigitalOcean from 246 to
> 280). Earlier revisions reported Stripe at 681 then 580 chains as these fixes
> removed false terminals. The machine-readable snapshots in
> `realworld_results/*.json` are regenerated from this same code. See
> `baseline_rescore.md` for the Gitea/Mattermost re-score and `scoped_eval.md`
> for the boundaries-scoped results and per-finding labelling.

All chains are evidence level `hypothetical` (static analysis never raises
evidence; only the replay harness does, and replay scenarios exist only for the
bundled reference API). No duplicate chain ids on any spec, and the `_MAX_CHAINS`
cap was never hit. Runtime is sub-second and memory under 60 MB even at ~850
operations, so there is no search-explosion or memory problem at this scale.

Outcome distribution:
- Stripe: fraud 383, data_theft 170, takeover 92, destruction 36.
- DigitalOcean: destruction 157, data_theft 119, takeover 23, fraud 16.

### A concrete blocker this evaluation found and fixed

On the first run, Stripe parsed 612 operations but extracted **1 field** and
found **0 chains**. Cause: `$ref` resolution inlined every operation (including
large response schemas) under a single document-wide node budget, which Stripe's
~1,500 densely referenced schemas exhausted almost immediately, so nearly every
request body resolved to empty. Fix: resolution is now lazy and per-operation,
touching only the parameters and request body that fields are read from, with
ancestor-based cycle detection instead of a shared inlining budget. After the
fix Stripe extracts 8,732 fields and the pipeline still runs in 0.75 s. (DO rose
from 1,532 to 4,160 fields for the same reason.)

## Manual review of high-severity findings

### Petstore (control): 0 findings — correct
A plain CRUD pet store has no free-text injection carrier and no outbound exit.
Reporting nothing is the right answer and shows the tool does not invent paths on
a simple API. (Before the taint-precision fix below it reported 4 chains driven
by the pet `name`/`tag` fields — all false positives.)

### Stripe: mostly over-reported, a few defensible
The highest-impact Stripe findings are weak. Representative example:

```
[data_theft] GET /v1/accounts/{account}/people :: first_name
   -> POST /v1/accounts/{account}/people/{person}
```

`first_name` / `account_holder_name` are data fields, not injection carriers,
and the "exit" is typically a `return_url`/`redirect` field rather than a
webhook that carries the read data. These are **not** defensible as stated.
Restricting entry points to genuine free-text carriers (see fix below) and
requiring a real outbound exit reduces Stripe to a handful of candidates (e.g.
`description` on `GET /v1/credit_notes` -> `POST /v1/credit_notes`,
`body` on `GET /v1/forwarding/requests` -> `POST /v1/forwarding/requests`), which
are plausible only under the unverified assumption that the agent both reads the
untrusted text and holds permission to call the write. Without a boundaries file
Stripe's count is dominated by generic "any tool reachable" emission and by
money-word terminals (hence fraud 383); these are speculative and labelled
generic.

### DigitalOcean: a defensible composed path
The strongest result in the whole evaluation:

```
[data_theft] description :: GET /v2/action-gateway/mcp-servers/{server_ref}
   -> POST /v2/action-gateway/mcp-servers         (specific, terminal_exit=True)
```

DO's action-gateway / agent surface lets an agent read an MCP server's
`description` (attacker-settable free text) and then register a new MCP server or
connection. This is a *composition of individually legitimate calls* — read a
description, create a connection — that a single-endpoint scanner (looking for
injection or broken-authz on one route) would not flag, and it lands squarely on
Overreach's thesis. It remains `hypothetical`: Overreach cannot confirm from the
spec that the same agent identity holds both permissions, nor that the
description is actually attacker-controlled. Stated honestly, it is a lead for a
reviewer, not a proven exploit.

## False-positive patterns and the fix applied

1. **Weak free-text hints (dominant FP driver).** `name` / `title` / `subject`
   matched data fields (`first_name`, `account_holder_name`, `display_name`) far
   more than injection carriers. Fix: these were removed from the taint
   free-text hints; only strong carriers (`body`, `comment`, `description`,
   `text`, `message`, `content`, `note`, `bio`) seed entry points. Effect:
   Petstore 4 -> 0 chains, DO 582 -> 315, taint links roughly halved on both
   large specs. A boundaries file can still mark a specific label field
   untrusted. (Was finding F-6 in the audit.)
2. **Generic "any tool reachable" emission.** Without a boundaries file,
   Overreach emits one generic chain per harmful terminal, assuming an injected
   agent can call any tool it holds. On Stripe this is the bulk of the count.
   This is intended and labelled `generic`; it is noise until scoped. The
   product answer is to supply a boundaries file, which is the tool's core
   differentiator, not to trust the unscoped generic list.
3. **Money-word terminals.** Lexical `MOVE_MONEY` inference on Stripe marks many
   endpoints as fraud terminals. The offline refiner already prunes money
   effects without commerce context; on Stripe the context genuinely is
   commerce, so these stay, but pairing them with arbitrary entries is
   speculative absent authority.

## What Overreach could not determine from the spec

- **Identity / delegated authority:** whether one agent identity actually holds
  both the read and the write permission in a chain. Assumed; never confirmed.
- **Ownership / tenancy:** cross-tenant reasoning needs a declared `tenant_param`
  and `agent_tenant`; neither public spec declares ownership enforcement, so
  cross-tenant findings are only reachable under an explicit boundaries file.
- **Real data flow:** that text read at step 1 actually reaches the destination
  at step N. Overreach pairs on the shared resource noun, which is a heuristic.
- **Semantic field presence:** a field extracted from a `oneOf`/`anyOf` branch is
  not present in every valid request. Each `Field` now carries `required` to
  mark this, and specs using these compositions emit one warning. Parser
  coverage is not semantic presence.

## Answer to the central question

> Can Overreach find a defensible attack path in an unfamiliar API that another
> security tool would overlook?

**Yes, but selectively.** On DigitalOcean it surfaced a defensible composed path
on the agent/action-gateway surface that a single-endpoint scanner would not
flag. On Stripe the defensible set is small and the raw output is dominated by
generic, unscoped emission. On the Petstore control it correctly found nothing.
The evaluation supports the product's own thesis: Overreach's value is in
composition and authority reasoning, and its signal depends on a boundaries file.
Unscoped on a large spec it over-reports, and the output should be read as leads
at `hypothetical` evidence, never as confirmed vulnerabilities.

## Limitations of this evaluation

- No boundaries files were supplied, so cross-tenant detection and scoped
  (specific, higher-confidence) findings were not exercised on these specs. A
  follow-up with hand-written boundaries would measure precision under scope.
- Plausibility judgements are the reviewer's, over the spec text alone; no
  running instance of Stripe or DigitalOcean was contacted (and must not be).
- Three specs (two large, one small control) is a starting sample, not a
  statistically representative corpus.
