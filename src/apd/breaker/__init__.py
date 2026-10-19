"""The Breaker.

Given the chains, work out which controls would break them. Model it as a
weighted hitting set: each chain must be hit by at least one control. Rather
than return one mathematically minimal set, return ranked alternatives, each
scored by chains covered, effort, and impact on legitimate workflows.

A control "breaks" a chain if it removes a step the chain depends on, marks the
entry field untrusted, or blocks the chain's exit.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from apd.chains import Chain

# v0.1 uses a greedy weighted set cover. An exact ILP solver is a later
# enhancement (see ADR 0003); greedy is optimal enough at this scale and keeps
# the dependency surface small.


class ControlKind(str, Enum):
    UNTRUSTED_FIELD = "mark_field_untrusted"
    APPROVAL = "require_approval"
    EGRESS_ALLOWLIST = "egress_allowlist"
    REMOVE_PERMISSION = "remove_permission"


@dataclass(frozen=True, slots=True)
class Control:
    kind: ControlKind
    target: str                  # field name or operation key
    effort: int                  # 1 (easy) .. 5 (hard)
    description: str


@dataclass(frozen=True, slots=True)
class Option:
    controls: tuple[Control, ...]
    chains_broken: int
    chains_total: int
    workflow_hits: int           # legitimate operations this option disturbs
    total_effort: int

    @property
    def score(self) -> tuple[int, ...]:
        # Higher coverage first, then fewer workflow hits, then less effort.
        return (self.chains_broken, -self.workflow_hits, -self.total_effort)


def _candidate_controls(chains: list[Chain]) -> list[Control]:
    out: dict[tuple[ControlKind, str], Control] = {}

    def add(kind: ControlKind, target: str, effort: int, desc: str) -> None:
        out.setdefault((kind, target), Control(kind, target, effort, desc))

    for ch in chains:
        add(ControlKind.UNTRUSTED_FIELD, ch.source_field or ch.source_op, 1,
            f"treat '{ch.source_field or ch.source_op}' as untrusted input to the agent")
        terminal = ch.steps[-1].op_key
        add(ControlKind.APPROVAL, terminal, 2,
            f"require human approval before {terminal}")
        if ch.outcome.value == "data_theft":
            add(ControlKind.EGRESS_ALLOWLIST, terminal, 3,
                f"restrict outbound destinations on {terminal}")
        add(ControlKind.REMOVE_PERMISSION, terminal, 4,
            f"remove the agent's permission for {terminal}")
    return list(out.values())


def _breaks(control: Control, chain: Chain) -> bool:
    if control.kind == ControlKind.UNTRUSTED_FIELD:
        return control.target in (chain.source_field, chain.source_op)
    # The other controls act on an operation; they break any chain using it.
    return any(s.op_key == control.target for s in chain.steps)


def _workflow_hits(control: Control, workflows: list[list[str]]) -> int:
    if control.kind == ControlKind.UNTRUSTED_FIELD:
        return 0
    return sum(1 for wf in workflows if control.target in wf)


def recommend(chains: list[Chain], workflows: list[list[str]] | None = None,
              *, max_options: int = 3) -> list[Option]:
    if not chains:
        return []
    workflows = workflows or []
    controls = _candidate_controls(chains)
    cover = {c: {i for i, ch in enumerate(chains) if _breaks(c, ch)}
             for c in controls}
    controls = [c for c in controls if cover[c]]
    whits = {c: _workflow_hits(c, workflows) for c in controls}

    options: list[Option] = []

    # Option 1: minimum weight, weight = effort + 2 * workflow hits.
    weighted = _greedy(chains, controls, cover,
                       key=lambda c: -(c.effort + 2 * whits[c]))
    options.append(_option(weighted, chains, cover, whits))

    # Option 2: fewest controls, ignore workflow cost (greedy by coverage).
    greedy = _greedy(chains, controls, cover, key=lambda c: len(cover[c]))
    options.append(_option(greedy, chains, cover, whits))

    # Option 3: least disruptive, prefer controls with zero workflow hits.
    safe = _greedy(chains, controls, cover,
                   key=lambda c: (whits[c] == 0, len(cover[c])))
    options.append(_option(safe, chains, cover, whits))

    # Dedupe by the set of controls, keep best-scoring order.
    uniq: dict[frozenset[tuple[ControlKind, str]], Option] = {}
    for o in options:
        k = frozenset((c.kind, c.target) for c in o.controls)
        if k not in uniq:
            uniq[k] = o
    ranked = sorted(uniq.values(), key=lambda o: o.score, reverse=True)
    return ranked[:max_options]


def _option(controls: list[Control], chains: list[Chain],
            cover: dict[Control, set[int]], whits: dict[Control, int]) -> Option:
    broken: set[int] = set()
    for c in controls:
        broken |= cover[c]
    return Option(
        controls=tuple(controls),
        chains_broken=len(broken),
        chains_total=len(chains),
        workflow_hits=sum(whits[c] for c in controls),
        total_effort=sum(c.effort for c in controls),
    )


def _greedy(chains: list[Chain], controls: list[Control],
            cover: dict[Control, set[int]],
            key: Callable[[Control], object]) -> list[Control]:
    """Cover every chain, picking at each step the control that covers the most
    still-uncovered chains, breaking ties by ``key`` (higher is better)."""
    remaining = set(range(len(chains)))
    chosen: list[Control] = []
    pool = list(controls)
    while remaining and pool:
        pool.sort(key=lambda c: (len(cover[c] & remaining),) + _as_tuple(key(c)),
                  reverse=True)
        best = pool[0]
        if not (cover[best] & remaining):
            break
        chosen.append(best)
        remaining -= cover[best]
        pool.remove(best)
    return chosen


def _as_tuple(v: object) -> tuple[object, ...]:
    return v if isinstance(v, tuple) else (v,)
