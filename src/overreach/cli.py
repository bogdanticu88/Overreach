"""Command line entry point.

v0.1 ships one read-only command: ``profile``. It parses a spec, runs
rule-based inference and taint pairing, and prints coverage statistics. It
finds no chains: that comes after the hand-written baseline exists, so the
baseline stays an independent check.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from overreach import __version__
from overreach.breaker import recommend
from overreach.chains import find_chains
from overreach.infer import infer_api, uncertain_operations
from overreach.ingest import load_path, merge_docs
from overreach.model import Api, EffectKind
from overreach.report import chain_to_dict, narrative, option_to_dict
from overreach.taint import find_links


def _load(path: str) -> Api:
    p = Path(path)
    if p.is_dir():
        docs = []
        for f in sorted(glob.glob(str(p / "*.yaml")) + glob.glob(str(p / "*.yml"))):
            data = yaml.safe_load(Path(f).read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                docs.append(data)
        return merge_docs(docs, title=p.name, version="merged")
    return load_path(p)


def _profile(api: Api) -> dict[str, object]:
    api = infer_api(api)
    method_counts: Counter[str] = Counter(op.method for op in api.operations)
    effect_counts: Counter[str] = Counter(
        e.kind.value for op in api.operations for e in op.effects
    )
    exit_ops = [op.key for op in api.operations if any(f.is_exit for f in op.fields)]
    identity_ops = [op.key for op in api.operations
                    if any(e.kind == EffectKind.CHANGE_IDENTITY for e in op.effects)]
    links = find_links(api)
    uncertain = uncertain_operations(api)
    return {
        "title": api.title,
        "version": api.version,
        "source_hash": api.source_hash,
        "operations": len(api.operations),
        "methods": dict(method_counts),
        "effects": dict(effect_counts),
        "exit_operations": len(exit_ops),
        "identity_operations": len(identity_ops),
        "write_read_links": len(links),
        "uncertain_operations": len(uncertain),
        "warnings": list(api.warnings),
        "sample_exit_ops": sorted(exit_ops)[:8],
        "sample_links": [
            {"object": lk.obj, "writer": lk.writer, "reader": lk.reader,
             "fields": list(lk.free_text_fields)}
            for lk in links[:8]
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="overreach", description=__doc__)
    parser.add_argument("--version", action="version", version=f"overreach {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("profile", help="parse a spec and print coverage stats")
    p.add_argument("spec", help="path to an OpenAPI file or a directory of fragments")
    p.add_argument("--json", action="store_true", help="emit JSON")

    s = sub.add_parser("scan", help="find attack chains and ranked fixes")
    s.add_argument("spec", help="path to an OpenAPI file or a directory of fragments")
    s.add_argument("--boundaries", help="path to a boundaries file (scopes findings)")
    s.add_argument("--top", type=int, default=10, help="chains to show")
    s.add_argument("--json", action="store_true", help="emit JSON")
    s.add_argument("--sarif", help="write SARIF 2.1.0 findings to this path")
    s.add_argument("--html", help="write a self-contained HTML report to this path")
    s.add_argument("--fail-on", choices=["none", "note", "warning", "error"],
                   default="none", help="exit non-zero if a finding at or above "
                   "this level is present")

    sub.add_parser("validate", help="run the bundled reference API demo end to end")

    args = parser.parse_args(argv)

    if args.cmd == "profile":
        api = _load(args.spec)
        report = _profile(api)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            for k, v in report.items():
                if k.startswith("sample_") or k in ("effects", "methods"):
                    print(f"{k}:")
                    print("  " + json.dumps(v, indent=2).replace("\n", "\n  "))
                else:
                    print(f"{k}: {v}")
        return 0

    if args.cmd == "scan":
        api = infer_api(_load(args.spec))
        bnd = None
        if args.boundaries:
            from overreach.boundaries import load_path as load_boundaries
            bnd = load_boundaries(args.boundaries)
        chains = find_chains(api, boundaries=bnd)
        top = chains[:args.top]
        options = recommend(chains)
        if args.json:
            print(json.dumps({
                "title": api.title,
                "chains_found": len(chains),
                "chains": [chain_to_dict(c) for c in top],
                "fix_options": [option_to_dict(o) for o in options],
            }, indent=2))
        else:
            specific = [c for c in chains if not c.generic]
            generic = [c for c in chains if c.generic]
            print(f"{api.title}: {len(chains)} finding(s), evidence: hypothetical "
                  f"from spec\n  {len(specific)} specific data-flow chain(s), "
                  f"{len(generic)} dangerous tool(s) reachable from untrusted input\n")
            for i, c in enumerate(top, 1):
                tag = "generic" if c.generic else "specific"
                extra = (f" (reachable from {c.entry_count} untrusted entries)"
                         if c.generic else "")
                print(f"[{i}] {c.chain_id}  {c.outcome.value}  [{tag}]{extra}")
                print("    " + narrative(c))
                print("    path: " + " -> ".join(s.op_key for s in c.steps))
                print()
            if generic:
                print("Note: generic findings assume an injected agent may call "
                      "any tool it holds.\n      Supply a boundaries file to limit "
                      "this to the agent's real scope.\n")
            if options:
                print("Ranked fixes (conditional prevention assumes each control "
                      "is actually enforced; verify by retest):")
                for j, o in enumerate(options, 1):
                    print(f"  Option {j}: would prevent {o.chains_prevented}/"
                          f"{o.chains_total} chains (covers {o.chains_covered}), "
                          f"{o.workflow_hits} workflow hit(s), effort {o.total_effort}")
                    for ctl in o.controls:
                        print(f"    - {ctl.description}")
        if args.sarif:
            from overreach.report import to_sarif
            with open(args.sarif, "w") as fh:
                json.dump(to_sarif(chains), fh, indent=2)
            if not args.json:
                print(f"\nSARIF written to {args.sarif}")
        if args.html:
            from overreach.report import to_html
            with open(args.html, "w") as fh:
                fh.write(to_html(top, options, api.title))
            if not args.json:
                print(f"HTML report written to {args.html}")
        if args.fail_on != "none":
            order = {"note": 1, "warning": 2, "error": 3}
            threshold = order[args.fail_on]
            worst = max((3 if c.impact >= 5 else 2 if c.impact == 4 else 1)
                        for c in chains) if chains else 0
            if worst >= threshold:
                return 1
        return 0

    if args.cmd == "validate":
        return _validate_demo()
    return 2


def _validate_demo() -> int:
    """Scan the bundled reference API, then validate chains by executing them
    with canary data and watching the canary leave."""
    import json as _json
    from importlib.resources import files

    from fastapi.testclient import TestClient

    from overreach.boundaries import load_text as load_boundaries
    from overreach.chains import find_chains
    from overreach.reference_api import app, reset_state
    from overreach.replay import validate_chain

    reset_state()
    client = TestClient(app)
    spec = _json.dumps(client.get("/openapi.json").json())
    api = infer_api(_load_text(spec))
    bnd_text = (files("overreach.reference_api") / "boundaries.yaml").read_text()
    bnd = load_boundaries(bnd_text)
    chains = find_chains(api, boundaries=bnd)
    print(f"Reference API: {len(chains)} finding(s) "
          f"(scoped by the bundled boundaries file).")
    print("Static analysis grades every finding 'hypothetical'. The replay "
          "harness then executes each\nchain's exact operation sequence against "
          "the in-process reference API with a unique canary.\n"
          "A 'validated' mark means that scripted, deterministic replay observed "
          "the effect; it is NOT\nevidence that a live LLM would independently "
          "choose these steps.\n")
    for ch in chains:
        reset_state()
        res = validate_chain(ch, TestClient(app))
        if res.evidence.value == "validated":
            mark = "static: hypothetical -> replay: VALIDATED (scripted)"
        else:
            mark = "static: hypothetical -> replay: not observed"
        print(f"[{ch.chain_id}] {ch.outcome.value}  {mark}")
        print(f"    {narrative(ch)}")
        if res.detail:
            print(f"    replay proof: {res.detail}"
                  + (f" (canary {res.canary})" if res.canary else ""))
        print()
    return 0


def _load_text(text: str) -> Api:
    from overreach.ingest import load_text
    return load_text(text)


if __name__ == "__main__":
    sys.exit(main())
