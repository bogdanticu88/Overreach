"""Overreach real-world evaluation harness.

Runs the pipeline (ingest -> infer -> find_chains) against one spec in an
isolated process and prints a JSON metrics record plus a sample of findings for
manual review. Memory is peak RSS for the whole process (resource.getrusage);
runtime is wall-clock per stage. No boundaries file is supplied, so every chain
is reported generic (the unfamiliar-API case: no declared authority).

Usage: python -I eval_harness.py <spec_path> [--sample N]
"""
from __future__ import annotations

import json
import resource
import sys
import time
from collections import Counter

from overreach.chains import _MAX_CHAINS, find_chains
from overreach.infer import infer_api
from overreach.ingest import IngestError, load_path


def _peak_mib() -> float:
    # ru_maxrss is KiB on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def main() -> int:
    path = sys.argv[1]
    sample_n = 8
    if "--sample" in sys.argv:
        sample_n = int(sys.argv[sys.argv.index("--sample") + 1])

    t0 = time.perf_counter()
    try:
        api = load_path(path)
    except IngestError as e:
        print(json.dumps({"spec": path, "error": f"ingest: {e}"}))
        return 1
    t_ingest = time.perf_counter() - t0

    t1 = time.perf_counter()
    api = infer_api(api)
    t_infer = time.perf_counter() - t1

    t2 = time.perf_counter()
    chains = find_chains(api)
    t_find = time.perf_counter() - t2

    # Field-level stats that bear on the parser-coverage-vs-semantics concern.
    total_fields = sum(len(op.fields) for op in api.operations)
    exit_fields = sum(1 for op in api.operations for f in op.fields if f.is_exit)

    by_outcome = Counter(c.outcome.value for c in chains)
    by_evidence = Counter(c.evidence.value for c in chains)
    specific = sum(1 for c in chains if not c.generic)
    generic = sum(1 for c in chains if c.generic)

    # Duplicate check: distinct chain ids vs total (find_chains already dedupes;
    # this confirms it on real input).
    ids = [c.chain_id for c in chains]
    dup = len(ids) - len(set(ids))

    rec = {
        "spec": path,
        "title": api.title,
        "version": api.version,
        "source_hash": api.source_hash,
        "operations_parsed": len(api.operations),
        "fields_extracted": total_fields,
        "exit_fields": exit_fields,
        "chains_total": len(chains),
        "chains_by_outcome": dict(by_outcome),
        "chains_by_evidence": dict(by_evidence),
        "specific": specific,
        "generic": generic,
        "duplicate_chain_ids": dup,
        "chain_cap_hit": len(chains) >= _MAX_CHAINS,
        "warnings_count": len(api.warnings),
        "warning_kinds": dict(Counter(
            w.split(":")[0].split("(")[0].strip() for w in api.warnings)),
        "time_ingest_s": round(t_ingest, 3),
        "time_infer_s": round(t_infer, 3),
        "time_find_s": round(t_find, 3),
        "time_total_s": round(t_ingest + t_infer + t_find, 3),
        "peak_rss_mib": round(_peak_mib(), 1),
    }

    # A sample of findings, highest-impact first, for manual plausibility review.
    ranked = sorted(chains, key=lambda c: (c.impact, c.plausibility), reverse=True)
    sample = []
    for c in ranked[:sample_n]:
        sample.append({
            "id": c.chain_id,
            "outcome": c.outcome.value,
            "impact": c.impact,
            "plausibility": c.plausibility,
            "evidence": c.evidence.value,
            "terminal_exit": c.terminal_exit,
            "source": {"op": c.source_op, "field": c.source_field},
            "path": [s.op_key for s in c.steps],
            "boundaries": list(c.boundaries),
            "entry_count": c.entry_count,
        })
    rec["sample"] = sample
    print(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
