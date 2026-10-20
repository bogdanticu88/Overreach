"""The Breaker.

Given the chains, work out which controls would interrupt them, and rank
alternative sets of controls.

The central distinction, which the previous version elided, is between

  * **proposed coverage** - a control is *positioned* on a chain (its target is
    a step of the chain or the chain's untrusted field), and
  * **verified-eligible prevention** - a control *technically enforces* a block
    on that chain, and its precondition for doing so holds.

A control is only counted as preventing a chain when it enforces (an egress
allowlist on the exfiltration exit, or removing the agent's permission for an
operation the chain depends on). Marking a field untrusted, or requiring human
approval, is treated as a mitigation that lowers likelihood, never as automatic
prevention: a label is not enforcement and a human may still approve. Nothing is
reported as *verified* until a control is actually enforced and the chain is
re-tested (see the replay harness); ``Option.verified`` stays ``False`` here.

Ranking is a deterministic weighted greedy set cover: prevention first, then
proposed coverage, then fewer legitimate-workflow disruptions, then less effort,
with a stable tie-break on control identity so output does not depend on dict
ordering.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from overreach.chains import Chain

# v0.1 uses a greedy weighted set cover. An exact ILP solver is a later
# enhancement (see ADR 0003); greedy is optimal enough at this scale and keeps
# the dependency surface small.


class ControlKind(str, Enum):
    UNTRUSTED_FIELD = "mark_field_untrusted"
    APPROVAL = "require_approval"
    EGRESS_ALLOWLIST = "egress_allowlist"
    REMOVE_PERMISSION = "remove_permission"


# Which control kinds are technical enforcement (can prevent) versus mitigations
# (lower likelihood, but do not block on their own).
_ENFORCING = frozenset({ControlKind.EGRESS_ALLOWLIST, ControlKind.REMOVE_PERMISSION})


@dataclass(frozen=True, slots=True)
class Control:
    kind: ControlKind
    target: str                  # field name or operation key
    effort: int                  # 1 (easy) .. 5 (hard)
    description: str

    @property
    def enforces(self) -> bool:
        """True if this control technically blocks, rather than only mitigating."""
        return self.kind in _ENFORCING


@dataclass(frozen=True, slots=True)
class Option:
    controls: tuple[Control, ...]
    chains_total: int
    # Conditional prevention: an enforcing control is positioned where it would
    # block the chain IF the enforcement assumption holds (the allowlist is
    # actually restrictive, the permission is actually removed). This is not
    # observed prevention; only a replay retest that enforces the control and
    # re-runs the chain can set `verified` and demonstrate observed prevention.
    chains_prevented: int        # conditional prevention (enforcement assumed)
    chains_covered: int          # chains any selected control is positioned on
    workflow_hits: int           # legitimate operations this option disturbs
    total_effort: int
    verified: bool = False       # True only after an enforced replay retest (observed)

    @property
    def score(self) -> tuple[int, ...]:
        # Prevention first, then coverage, then fewer workflow hits, then less
        # effort. (Negatives so that "more" sorts ahead under reverse=True.)
        return (self.chains_prevented, self.chains_covered,
                -self.workflow_hits, -self.total_effort)


def _candidate_controls(chains: list[Chain]) -> list[Control]:
    out: dict[tuple[ControlKind, str], Control] = {}

    def add(kind: ControlKind, target: str, effort: int, desc: str) -> None:
        out.setdefault((kind, target), Control(kind, target, effort, desc))

    for ch in chains:
        src = ch.source_field or ch.source_op
        add(ControlKind.UNTRUSTED_FIELD, src, 1,
            f"treat '{src}' as untrusted input to the agent "
            "(mitigation: routes to review, does not block on its own)")
        terminal = ch.steps[-1].op_key
        add(ControlKind.APPROVAL, terminal, 2,
            f"require human approval before {terminal} "
            "(mitigation: reduces risk, but a human may still approve)")
        # An egress allowlist only helps when the terminal actually makes a
        # caller-named outbound request; a cross-tenant read or a sink write
        # exfiltrates by other means and is not prevented by it.
        if ch.outcome.value == "data_theft" and ch.terminal_exit:
            add(ControlKind.EGRESS_ALLOWLIST, terminal, 3,
                f"restrict outbound destinations on {terminal} "
                "(prevents exfiltration to attacker-named hosts)")
        add(ControlKind.REMOVE_PERMISSION, terminal, 4,
            f"remove the agent's permission for {terminal} "
            "(prevents: the agent can no longer call it)")
    return list(out.values())


def _covers(control: Control, chain: Chain) -> bool:
    """Proposed coverage: the control is positioned on this chain."""
    if control.kind == ControlKind.UNTRUSTED_FIELD:
        return control.target in (chain.source_field, chain.source_op)
    return any(s.op_key == control.target for s in chain.steps)


def _prevents(control: Control, chain: Chain) -> bool:
    """Verified-eligible prevention: the control enforces a block on this chain
    and its precondition holds. Enforcement alone is not enough; the control has
    to actually sit where it interrupts the path."""
    if not control.enforces:
        return False
    if control.kind == ControlKind.REMOVE_PERMISSION:
        # Removing the agent's permission for any operation the chain depends on
        # (its entry read or its terminal effect) breaks the path.
        return any(s.op_key == control.target for s in chain.steps)
    if control.kind == ControlKind.EGRESS_ALLOWLIST:
        # An egress allowlist only prevents exfiltration, and only when it sits
        # on a terminal that actually makes a caller-named outbound request.
        return (chain.outcome.value == "data_theft" and chain.terminal_exit
                and control.target == chain.steps[-1].op_key)
    return False


def _workflow_hits(control: Control, workflows: list[list[str]]) -> int:
    # Marking a field untrusted disrupts no operation; the others gate or remove
    # an operation and so can disturb legitimate workflows that use it.
    if control.kind == ControlKind.UNTRUSTED_FIELD:
        return 0
    return sum(1 for wf in workflows if control.target in wf)


def _ident(c: Control) -> tuple[str, str]:
    return (c.kind.value, c.target)


def recommend(chains: list[Chain], workflows: list[list[str]] | None = None,
              *, max_options: int = 3) -> list[Option]:
    if not chains:
        return []
    workflows = workflows or []
    controls = _candidate_controls(chains)
    covers = {c: {i for i, ch in enumerate(chains) if _covers(c, ch)} for c in controls}
    prevents = {c: {i for i, ch in enumerate(chains) if _prevents(c, ch)} for c in controls}
    controls = [c for c in controls if covers[c]]
    whits = {c: _workflow_hits(c, workflows) for c in controls}

    enforcing = [c for c in controls if c.enforces and prevents[c]]

    options: list[Option] = []

    # Option 1: prevention with least disruption. Cover every chain using only
    # enforcing controls, preferring low effort + low workflow impact.
    o1 = _greedy(chains, enforcing, prevents,
                 key=lambda c: -(c.effort + 2 * whits[c]))
    options.append(_option(o1, chains, covers, prevents, whits))

    # Option 2: fewest enforcing controls (greedy by prevention coverage).
    o2 = _greedy(chains, enforcing, prevents, key=lambda c: len(prevents[c]))
    options.append(_option(o2, chains, covers, prevents, whits))

    # Option 3: defence in depth. Take the least-disruptive enforcing set, then
    # layer mitigations (untrusted-field, approval) onto any chain not yet
    # covered. Mitigations raise coverage, never prevention.
    mitigations = [c for c in controls if not c.enforces]
    layered = list(o1)
    covered_idx: set[int] = set()
    for c in layered:
        covered_idx |= covers[c]
    extra = _greedy_cover_remaining(chains, mitigations, covers, covered_idx,
                                    key=lambda c: -(c.effort + 2 * whits[c]))
    options.append(_option(layered + extra, chains, covers, prevents, whits))

    # Dedupe by the set of controls, then rank deterministically.
    uniq: dict[frozenset[tuple[str, str]], Option] = {}
    for o in options:
        k = frozenset(_ident(c) for c in o.controls)
        if k and k not in uniq:
            uniq[k] = o
    ranked = sorted(uniq.values(),
                    key=lambda o: o.score + (tuple(sorted(
                        _ident(c) for c in o.controls)),),
                    reverse=True)
    return ranked[:max_options]


def _option(controls: list[Control], chains: list[Chain],
            covers: dict[Control, set[int]], prevents: dict[Control, set[int]],
            whits: dict[Control, int]) -> Option:
    cov: set[int] = set()
    prev: set[int] = set()
    for c in controls:
        cov |= covers[c]
        prev |= prevents[c]
    return Option(
        controls=tuple(controls),
        chains_total=len(chains),
        chains_prevented=len(prev),
        chains_covered=len(cov),
        workflow_hits=sum(whits[c] for c in controls),
        total_effort=sum(c.effort for c in controls),
    )


def _greedy(chains: list[Chain], controls: list[Control],
            reach: dict[Control, set[int]],
            key: Callable[[Control], object]) -> list[Control]:
    """Cover every chain using ``reach`` sets, picking at each step the control
    that reaches the most still-uncovered chains, breaking ties by ``key``
    (higher is better) and finally by control identity (deterministic)."""
    remaining = set(range(len(chains)))
    chosen: list[Control] = []
    pool = list(controls)
    while remaining and pool:
        pool.sort(key=lambda c: (len(reach[c] & remaining),) + _as_tuple(key(c))
                  + (_ident(c),), reverse=True)
        best = pool[0]
        if not (reach[best] & remaining):
            break
        chosen.append(best)
        remaining -= reach[best]
        pool.remove(best)
    return chosen


def _greedy_cover_remaining(chains: list[Chain], controls: list[Control],
                            covers: dict[Control, set[int]], already: set[int],
                            key: Callable[[Control], object]) -> list[Control]:
    remaining = set(range(len(chains))) - already
    chosen: list[Control] = []
    pool = list(controls)
    while remaining and pool:
        pool.sort(key=lambda c: (len(covers[c] & remaining),) + _as_tuple(key(c))
                  + (_ident(c),), reverse=True)
        best = pool[0]
        if not (covers[best] & remaining):
            break
        chosen.append(best)
        remaining -= covers[best]
        pool.remove(best)
    return chosen


def _as_tuple(v: object) -> tuple[object, ...]:
    return v if isinstance(v, tuple) else (v,)
