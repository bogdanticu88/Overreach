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

apd profile <spec>              # coverage statistics
apd scan <spec>                 # find chains and ranked fixes
apd validate                    # run the reference API demo end to end
```

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
