# Writing a boundaries file

A boundaries file tells Overreach what the agent is actually allowed to do. It is
optional, but without it Overreach assumes an injected agent can call *any*
operation the spec exposes, which is noisy on a large API. With it, Overreach
scopes findings to the agent's real authority and can reason about tenancy.

Pass it with `overreach scan <spec> --boundaries <file>`.

## The shape

```yaml
agent:
  acts_as: support-refunds-agent     # a name for the principal (free text)
  allowed_ops:                       # glob patterns on "METHOD /path" op keys
    - "GET /v1/customers*"
    - "POST /v1/refunds"
  tenant: acme                       # the tenant THIS agent belongs to (optional)

untrusted_fields:                    # fields that carry attacker-authored text
  - "customer.description"
  - "dispute.evidence"

tenants:
  key: owner                         # the path parameter that identifies a tenant
```

Every section is optional. An empty file means "unknown scope" (same as no file).

## Each field

- **`agent.acts_as`** — a label for the principal the agent runs as. It appears
  in the boundary descriptions on findings. Purely descriptive.

- **`agent.allowed_ops`** — the operations this principal may call, as
  [fnmatch](https://docs.python.org/3/library/fnmatch.html) globs against each
  operation's key, which is `METHOD /path` exactly as the spec writes the path
  (e.g. `GET /v2/agents/{agent_id}`). `*` matches within a path. List only what
  the agent can really do: an entry's read reach and a harmful terminal are both
  filtered through this, so an over-broad list re-introduces noise and a
  too-narrow one hides real chains. When omitted, every operation is assumed
  reachable.

- **`agent.tenant`** — the tenant identifier the agent itself belongs to (e.g.
  the org slug, the account id). Set it only together with `tenants.key`; it turns
  on cross-tenant detection (a tenant-scoped read the agent can call becomes a
  data-theft risk, because the attacker can supply another tenant's id and the
  spec rarely shows an ownership check).

- **`untrusted_fields`** — fields carrying text an outside party can author, as a
  bare field name or `Object.field`. These seed entry points in addition to the
  ones the taint pass finds, which matters when the data is written out of band
  (a label, a name, a config value you know users set). Overreach's own taint
  heuristics only treat strong free-text fields (body, comment, description,
  message, …) as entries; declare a weaker field here if it is attacker-settable
  in your deployment.

- **`tenants.key`** — the path parameter that names a tenant, e.g. `owner` in
  `/repos/{owner}/{repo}` or `team_id`. Overreach reads the last dotted segment,
  so `tenants.key: repo.owner` is stored as `owner`.

## How to derive one

1. **Name the role.** What is this agent for — support, deploys, a chatbot? Its
   job defines its scope.
2. **List what it may call.** Start from the operations the role needs and widen
   with globs. Prefer reads broadly and writes narrowly; omit anything the role
   should never do (webhooks, key/credential management, account changes).
3. **Mark untrusted inputs.** Which fields does the agent read that outsiders
   write? Comments, descriptions, uploaded content, display names.
4. **Decide tenancy.** If one deployment serves many tenants and the agent is
   scoped to one, set `tenants.key` and `agent.tenant`. If the API is
   single-account per credential, leave both out.
5. **State the unknowns.** Fine-grained scopes (restricted API keys, custom token
   scopes) are often not in the spec. Assume the scope you model and say so in a
   comment; widen `allowed_ops` if the real credential is broader.

## Worked examples

`examples/stripe_boundaries.yaml` and `examples/digitalocean_boundaries.yaml`
each model one realistic restricted agent, with a header documenting the agent's
identity and operations, the attacker-controlled inputs, the trust and ownership
boundaries, the permitted versus prohibited effects, and the unknown
authorization relationships. `examples/reference_boundaries.yaml` is the minimal
one used by the bundled demo. Start from whichever is closest and trim.

## A caution

A boundaries file is a model of authority, not a guarantee. Overreach still
cannot confirm from a spec that one identity holds two permissions at once, or
that a tenant parameter is unchecked. Scoped findings remain `hypothetical`
leads; the boundaries file makes them sharper, not proven.
