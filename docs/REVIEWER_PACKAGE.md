# Independent reviewer package

A compact, self-contained brief for a second security engineer. It gives you
enough to challenge Overreach's reasoning on your own terms — the claims, the one
representative finding, the assumptions behind it, and how to reproduce it — plus
the questions we most want pushback on. You should not have to trust the
project's own conclusions; everything here is reproducible.

## 1. Threat model

Overreach addresses one question: **what could an AI agent be manipulated into
doing with an API, using only permissions it already holds?** The agent is a
capable worker with no judgement about what is off-limits. It reads text other
people authored (comments, descriptions, file contents) and acts with a
delegated identity. Individual API calls are each authorized; the harm is in the
*sequence*. The attacker's capability is to plant text the agent will read, not
to hold the agent's credentials.

In scope: chains from an attacker-controlled input to a harmful terminal
(exfiltration, takeover, destruction, fraud, cost), reasoned from an OpenAPI 3.x
spec plus an optional authority (boundaries) file. Out of scope: runtime
exploitation, confirming an LLM would choose the steps, and anything requiring a
live instance.

## 2. Architecture (one pass)

```
spec -> ingest -> infer (+offline refine) -> taint -> chains -> breaker -> report
                                                         ^
                                     boundaries file (authority) scopes here
   replay: execute a chain's exact op sequence vs the bundled reference API
```

- **ingest** — safe OpenAPI load (no execution, no external `$ref` fetch, lazy
  bounded resolution).
- **infer** — per-operation effects with provenance + confidence; identity/money
  require a writing method.
- **taint** — free-text writer→reader links on a specific resource noun.
- **chains** — bounded, deterministic search entry→terminal; exfil sinks limited
  to communication surfaces; boundaries scope reach and enable cross-tenant.
- **breaker** — ranked controls, separating coverage from conditional prevention.
- **replay** — the only path to `validated`, bound to the exact op sequence.

Evidence ladder: `hypothetical` (spec) → `simulated` (reserved) → `validated`
(exact sequence executed against an authorised implementation, canary observed).
`validated` means the API permits the sequence, not that an LLM would choose it.

## 3. One representative finding

From DigitalOcean's public spec (bundled), scoped by
`examples/digitalocean_boundaries.yaml`:

```
data_theft (hypothetical)
  entry : GET /v2/action-gateway/mcp-servers/{server_ref}   field: description
  term  : POST /v2/action-gateway/mcp-servers               (caller-named endpoint)
  boundary: untrusted text drives a privileged, caller-named outbound registration
```

Read a composition a per-endpoint scanner would not flag: an agent reads an MCP
server's `description` (free text) and is steered to register a new MCP server /
connection whose `endpoint` the attacker names.

## 4. Evidence and assumptions (what we can and cannot stand behind)

Established from the spec (reproducible):
- `description` is a request-body field on `POST`/`PATCH .../mcp-servers` and is
  returned by the `GET`s — so it is writable by one party and read by the agent.
- `POST .../mcp-servers` carries `endpoint` (and OAuth URLs) — a caller-named
  outbound destination.
- Both the read and the create are within the modelled agent's authority.

Assumed, **not** established (the finding stays `hypothetical`):
- that the `description` author is an adversary the agent does not trust;
- that one agent identity holds both the read and the create permission;
- that the agent will actually follow injected instructions.

We do **not** claim this is exploitable. There is no observed evidence, and none
can be produced without an authorised DigitalOcean instance (which must not be
contacted).

## 5. Reproduction

```bash
pip install -e ".[demo]"
# the offline flagship story (reference API), exits 0 only if it leaks then is prevented:
python demo/flagship_demo.py
# the representative finding (needs the DigitalOcean spec, see docs/baselines/*):
#   fetch per docs/baselines/realworld_eval.md, bundle multi-file with redocly,
#   then:
overreach scan <do_bundled.json> --boundaries examples/digitalocean_boundaries.yaml
# baseline re-score (needs Gitea/Mattermost specs per baseline_rescore.md):
OVERREACH_SPECS=<dir> python -I docs/baselines/rescore.py
```

Quality gates: `ruff check src tests`, `mypy src/overreach`, `pytest -q`,
`bandit -r src/overreach`.

## 6. Known limitations

- Unscoped output on large specs is dominated by generic reach; a boundaries file
  is required for signal.
- Scoped precision is a single-reviewer defensibility estimate (Stripe 3/3, DO
  20/21), not a validated exploit rate.
- Multi-file specs must be bundled first (external `$ref`s not fetched).
- Not modelled: code-execution/plugin-install, config tampering, cross-org
  federation, AI-recap injection, visibility downgrades, trigger-step terminals.
- Data flow is paired on the shared resource noun — a heuristic, not proven flow.

## 7. Questions we want challenged

1. **Boundaries realism.** Are `examples/stripe_boundaries.yaml` and
   `digitalocean_boundaries.yaml` plausible restricted roles, or have we scoped
   them to make findings look good? Where would a real deployment differ?
2. **The representative finding.** Is the MCP chain a defensible lead, or does a
   DigitalOcean authorization rule we cannot see from the spec defeat it?
3. **Evidence honesty.** Does anything in the output read as a stronger claim
   than "the API permits this sequence"? Is the `hypothetical`/`validated` line
   drawn in the right place?
4. **Sink heuristic.** We restrict exfil sinks to communication-surface objects.
   Does that miss a real exfil surface, or still over-fire?
5. **Labelling.** Our scoped precision rests on one reviewer's PLAUSIBLE/WEAK
   criteria (`scoped_eval.md`). Re-label a sample blind and see if you agree.
6. **Recall vs precision.** The three Gitea misses are trigger-step terminals
   whose setup op we flag. Is counting them as misses the right call?
7. **What would make you dismiss a finding?** We want the failure mode that makes
   a working security engineer stop reading.
