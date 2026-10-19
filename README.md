# Agent Attack Path Discovery (working name)

Finds chains of individually legitimate API operations that combine into a
harmful outcome, says how strong the evidence for each is, and ranks the
controls that would break them.

> Status: pre-alpha. The full v0.1 pipeline runs end to end on the bundled
> reference API: scan a spec for attack chains, then validate them by executing
> the chain and watching a canary leave. See the design document for the
> evidence model and `docs/SPIKE_NOTES.md` for what running on real specs found.

## What works today

- Safe OpenAPI 3.x ingest (JSON or YAML, single file or a directory of
  fragments). Nothing from a spec is executed; external `$ref` targets are
  never fetched.
- Rule-based effect inference with provenance (`declared` / `inferred` /
  `observed`) and a confidence on every effect.
- Taint pairing on the specific resource object, with dynamic container
  detection so broad nouns like `repo` do not link everything.
- Chain finding: specific multi-step data flows, plus generic cross-domain
  reach collapsed to one finding per dangerous tool.
- A ranked Breaker: control options with coverage, effort and workflow impact.
- Evidence levels in the type system: `hypothetical` from the spec, `validated`
  only after the chain is executed against a real implementation.
- A linter-clean reference API carrying planted chains, and a validation harness
  that proves them with canary data.

## Try it

```bash
pip install -e ".[dev]"

apd profile <spec>                       # coverage statistics
apd scan <spec>                          # find chains and ranked fixes
apd scan <spec> --boundaries <file>      # scope findings to the agent's authority
apd scan <spec> --sarif out.sarif        # SARIF for GitHub code scanning
apd scan <spec> --html report.html       # a shareable HTML report
apd scan <spec> --fail-on error          # non-zero exit for CI gating
apd validate                             # run the reference API demo end to end
```

### What the demo shows

`apd validate` scans the bundled reference API, a code host built to score
well on agent-readiness linters, then proves chains by executing them:

```
Reference API: 2 finding(s) (scoped by the bundled boundaries file).

[df301d8e0d43] data_theft: VALIDATED
    An attacker writes text into body that the agent later reads at
    GET .../comments. Following that text, the agent can exfiltrate data by
    reaching POST .../hooks in 2 steps, each individually permitted.
    proof: canary reached the attacker destination through the webhook

[a3af9754ae4d] data_theft: VALIDATED
    ... the agent can exfiltrate data by reaching GET .../contents/{path} ...
    Boundary crossed: crosses tenant boundary: no ownership check for 'owner'.
    proof: agent read another tenant's private file; no ownership check
```

A boundaries file declares what the agent may do, which fields are untrusted,
and which path parameter identifies a tenant. Supplying one scopes "any tool
reachable" down to what the agent can actually touch, turns credible reach into
specific findings, and labels the boundary each chain crosses. See
`src/apd/reference_api/boundaries.yaml` for an example.

## Safety

This tool is built to be pointed at untrusted input. It never executes or
fetches anything from a spec, parses YAML in safe mode only, and bounds size
and reference depth. See `SECURITY.md`.

## Develop

```bash
pip install -e ".[dev]"
python -m pytest -q
python -m mypy src/apd
```
