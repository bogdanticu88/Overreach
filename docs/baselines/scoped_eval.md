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

Numbers below are **after** the three false-positive fixes landed (the
communication-surface sink restriction, ownership-gated transfer/rename, and the
provider/redirect/subject-email egress exclusion). The pre-fix figures are noted
inline for comparison.

| Spec | Unscoped total | specific / generic | Scoped total | specific / generic | Eliminated | Scoped-only | Runtime | Peak RSS |
|---|---|---|---|---|---|---|---|---|
| Stripe | 469 | 281 / 188 | **3** | 3 / 0 | 469 | 3 | ~0.4 s | 59 MB |
| DigitalOcean | 280 | 97 / 183 | **21** | 21 / 0 | 259 | 0 | ~0.3 s | 45 MB |

On DigitalOcean the 21 scoped findings are a subset of the unscoped set
(eliminated 259 = 280 − 21, scoped-only 0). On Stripe they are not: the
boundaries file's `untrusted_fields` seed 3 entry points the unscoped taint pass
did not, so all 469 unscoped chains are eliminated and 3 scoped-only chains are
introduced. "Eliminated" and "Scoped-only" are therefore counted independently,
not as `unscoped − scoped`.

Scoping removes every `generic` ("any tool reachable") finding and most specific
ones, leaving only chains whose entry and terminal are both inside the agent's
declared authority. "Scoped-only" (3 on Stripe) are chains introduced because the
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

| Spec | Scoped | Plausible | Weak | Est. precision | (pre-fix) |
|---|---|---|---|---|---|
| Stripe | 3 | 3 | 0 | 100% | (was ~43%) |
| DigitalOcean | 21 | 20 | 1 | ~95% | (was ~50%) |

### Plausible findings (examples)
- Stripe: injected text in a charge/customer description steering a support agent
  to `POST /v1/refunds` or `POST /v1/charges/{charge}/refunds` — financial loss
  within the agent's real authority.
- DigitalOcean: injected text in an MCP server `description` steering the agent to
  `POST /v2/action-gateway/mcp-servers` / `connections` / `agents/triggers` with a
  caller-named endpoint (exfil / backdoor), or to `POST /v2/gen-ai/.../keys` /
  `api_keys` (persistent credential).

### The three false-positive patterns, now fixed
The earlier revision of this evaluation reported three weak patterns. All three
were confirmed classification defects and fixed (see `test_precision.py`):
- **Same-domain create via the sink-writer heuristic** (was 17 of DO's weak):
  the exfiltration sink is now restricted to communication-surface objects, so
  creating a toolbelt / scenario_set / router is no longer flagged as data theft.
- **"transfer"-word takeover** (was 5 of DO's weak): transfer/rename is an
  identity effect only on an ownable object, so a workspace file transfer is no
  longer a takeover.
- **Provider/subject URL+email as exfil** (was 4 of Stripe's weak): the Stripe
  dispute chains were driven by `customer_email_address`, a subject attribute,
  now excluded from egress along with provider/redirect URLs.

The one remaining DigitalOcean weak finding (`-> POST
/v2/agents/sessions/policy/validate`, flagged takeover with an exit field) is a
borderline case left as an honest weak, not force-fixed.

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
output on in-authority chains. After the three false-positive fixes, nearly all
survivors are defensible hypotheticals (Stripe 3/3, DigitalOcean 20/21). The
honest position for v0.1: Overreach with a boundaries file produces a small,
reviewable set of genuine leads (the DO MCP/credential family, the Stripe refund
family) at `hypothetical` evidence. It is a triage aid, not a vulnerability
oracle, and the precision figures are single-reviewer defensibility judgements,
not validated exploit rates.
