# Boundaries-scoped evaluation

This measures what an authority boundaries file does to Overreach's output on two
large real specifications, and labels the scoped findings by hand. It is the
evidence-quality gate before v0.1: does scoping sharpen signal, and are the
surviving findings defensible?

Specs and provenance are as in `realworld_eval.md`. Boundaries files:
`examples/stripe_boundaries.yaml`, `examples/digitalocean_boundaries.yaml`. Both
model one realistic *restricted* agent, use only capabilities visible in the
public spec, and state their assumptions (identity and operations, attacker
inputs, trust/ownership boundaries, permitted vs prohibited effects, unknown
authorization). Neither invents permissions.

## Effect of scoping

| Spec | Unscoped total | specific / generic | Scoped total | specific / generic | Eliminated | Scoped-only | Runtime | Peak RSS |
|---|---|---|---|---|---|---|---|---|
| Stripe | 580 | 364 / 216 | **7** | 7 / 0 | 577 | 4 | ~0.5 s | 59 MB |
| DigitalOcean | 315 | 91 / 224 | **44** | 44 / 0 | 271 | 0 | ~1.0 s | 59 MB |

Scoping removes every `generic` ("any tool reachable") finding and most specific
ones, leaving only chains whose entry and terminal are both inside the agent's
declared authority. "Scoped-only" (4 on Stripe) are chains introduced because the
boundaries file's `untrusted_fields` declared entry points the unscoped taint
pass did not seed. Runtime and memory are unchanged (sub-second, <60 MB).

**Fewer is not automatically better.** The reduction is only an improvement if
the eliminated findings were noise and the survivors are defensible. The manual
labelling below tests that.

## Manual labelling of the scoped findings

Every scoped finding (all 7 Stripe, all 44 DigitalOcean) was labelled by hand.

**Criterion for PLAUSIBLE** (a defensible *hypothetical*, not a confirmed
exploit): the entry is a genuine outside-authorable free-text field **and** the
terminal is a genuinely harmful effect the role's authority supports —
- fraud via a money-moving write (refund / pay),
- data theft via an outbound registration whose exit is a caller-named endpoint
  (an MCP server, connection, trigger, agent, knowledge base, data source, or
  OAuth token),
- takeover via creating credential material (an API key, token, or OAuth token),
- destruction via a remove / delete / clear op.

**WEAK** otherwise. Ground truth is not established (no authorised instance was
contacted), so these are defensibility judgements, and the precision figures are
estimates, not validated rates.

| Spec | Scoped | Plausible | Weak | Est. precision |
|---|---|---|---|---|
| Stripe | 7 | 3 | 4 | ~43% |
| DigitalOcean | 44 | 22 | 22 | ~50% |

### Plausible findings (examples)
- Stripe: injected text in a charge/customer description steering a support agent
  to `POST /v1/refunds` or `POST /v1/charges/{charge}/refunds` — financial loss
  within the agent's real authority.
- DigitalOcean: injected text in an MCP server `description` steering the agent to
  `POST /v2/action-gateway/mcp-servers` / `connections` / `agents/triggers` with a
  caller-named endpoint (exfil / backdoor), or to `POST /v2/gen-ai/.../keys` /
  `api_keys` (persistent credential).

### False-positive patterns in the WEAK set (reported, not fixed)
- **Same-domain create via the sink-writer heuristic** (17 of DO's weak): `GET
  toolbelts -> POST toolbelts`, `GET scenario_sets -> POST scenario_sets`, etc.
  Creating another object in the same domain whose description is read back is
  flagged as data theft, but it is not exfiltration.
- **"transfer"/"session" word takeover** (5 of DO's weak): `-> POST
  /v2/agents/sessions/{id}/workspace/transfers` is tagged takeover because
  "transfer" is an identity/irreversible word; a workspace file transfer is not
  account takeover.
- **Dispute evidence as exfil** (4 of Stripe's weak): `-> POST
  /v1/disputes/{dispute}` has URL-shaped evidence fields, but those go to Stripe
  and the bank, not to an attacker-controlled destination.

These are candidate precision fixes (narrow the sink-writer heuristic to
cross-domain reads; treat "transfer" as identity only on account/ownership
objects; distinguish provider-bound URL fields from caller-named egress). They
are **not** fixed here, to avoid new detection changes at the release gate.

## Validation of the DigitalOcean MCP finding

The flagged chain: `GET /v2/action-gateway/mcp-servers/{server_ref}`
(`description`) → `POST /v2/action-gateway/mcp-servers`.

| Question | Finding from the spec |
|---|---|
| Is the description genuinely attacker-controlled? | **Partly.** `description` is a request-body field on `POST` and `PATCH .../mcp-servers`, and is returned by the `GET`s. It is settable by whoever can create/update an MCP server and read back by the agent. The spec confirms the field is writable and readable; it cannot confirm the writer is an adversary. |
| Can the agent encounter it? | **Yes.** The `GET` list/detail reads are in the modelled agent's scope. |
| Is the registration operation reachable? | **Yes.** `POST /v2/action-gateway/mcp-servers` is in scope and carries `endpoint` and `oauth_*_url` fields the finder classifies as a caller-named outbound destination (`send_out`). |
| Does the same principal hold both read and create authority? | **Unknown.** The spec cannot show one identity holds both. The boundaries file assumes it; this is an explicit, unverified assumption. |
| Is a meaningful trust boundary crossed? | **Yes, if the description writer is untrusted:** untrusted text drives a privileged registration pointing at an attacker endpoint. |
| Does the outcome require unproven agent behavior? | **Yes.** It requires the agent to actually follow the injected instruction and register the server. Never observed. |

**Disposition:** retained as **hypothetical** with the two explicit assumptions
(the description author is untrusted; one agent identity holds both read and
create authority). It is a defensible lead a reviewer would want to check, and a
composition a per-endpoint scanner would miss. It is **not** described as an
exploitable vulnerability; there is no observed evidence, and Overreach cannot
produce any without an authorised DigitalOcean instance (which must not be
contacted).

## Reading

Scoping does what it should: it removes the generic noise and concentrates the
output on in-authority chains. Even scoped, roughly half of the survivors are
weak under hand review, driven by three nameable heuristic patterns. The honest
position for v0.1: Overreach with a boundaries file produces a small,
reviewable set containing genuine leads (the DO MCP/credential family, the
Stripe refund family), mixed with heuristic false positives a human triages. It
is a triage aid at `hypothetical` evidence, not a vulnerability oracle.
