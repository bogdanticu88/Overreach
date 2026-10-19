# Agent Attack Path Discovery (working name)

Finds chains of individually legitimate API operations that combine into a
harmful outcome, says how strong the evidence for each is, and ranks the
controls that would break them.

> Status: pre-alpha, Phase 0. This repository is a feasibility spike plus the
> core effect model. It does **not** yet find chains. See the design document
> for scope and the evidence model.

## What works today

- Safe OpenAPI 3.x ingest (JSON or YAML, single file or a directory of
  fragments). Nothing from a spec is executed; external `$ref` targets are
  never fetched.
- Rule-based effect inference with provenance (`declared` / `inferred` /
  `observed`) and a confidence on every effect.
- Taint pairing: where one operation writes an object and another reads it
  back, with the free-text fields an outside party could set.
- `apd profile <spec>`: coverage statistics, no chains.

## Safety

This tool is built to be pointed at untrusted input. It never executes or
fetches anything from a spec, parses YAML in safe mode only, and bounds size
and reference depth. See `SECURITY.md`.

## Develop

```bash
pip install -e ".[dev]"
python -m pytest -q
python -m mypy src/apd
apd profile path/to/openapi.json
```
