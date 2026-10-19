"""Chain finder.

A chain is a path of individually legitimate operations that starts where an
agent ingests attacker-controlled text and ends at a harmful effect. We build a
directed graph over operations and search, with bounded depth, from every
untrusted-read entry to every harmful terminal.

Pure analysis over the parsed, inferred model plus taint links. No execution,
no network. Evidence here is always HYPOTHETICAL; raising it to VALIDATED is
the replay harness's job.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from apd.boundaries import Boundaries
from apd.model import Api, EffectKind, Operation
from apd.taint import WriteReadLink, find_links

_MAX_DEPTH = 4            # bound on same-domain data-flow paths
_MAX_CHAINS = 5000        # defensive cap on very large specs
_MAX_FANOUT = 12          # an object in more ops than this is a container

# Broad container nouns link almost everything in an API and form huge cliques
# in the object graph. They are excluded from data-flow adjacency; cross-domain
# reach is handled by direct entry-to-terminal emission instead.
_CONTAINER_NOUNS = frozenset((
    "repo", "repositorie", "repository", "org", "organization", "organisation",
    "user", "team", "group", "project", "owner", "enterprise", "admin",
    "account", "workspace", "channel", "namespace",
))


class Outcome(str, Enum):
    DATA_THEFT = "data_theft"
    DESTRUCTION = "destruction"
    TAKEOVER = "takeover"
    FRAUD = "fraud"
    COST = "cost"


class Evidence(str, Enum):
    HYPOTHETICAL = "hypothetical"
    SIMULATED = "simulated"
    VALIDATED = "validated"


# Which terminal effect maps to which harmful outcome.
_TERMINAL: dict[EffectKind, Outcome] = {
    EffectKind.SEND_OUT: Outcome.DATA_THEFT,
    EffectKind.CHANGE_IDENTITY: Outcome.TAKEOVER,
    EffectKind.MOVE_MONEY: Outcome.FRAUD,
}


@dataclass(frozen=True, slots=True)
class Step:
    op_key: str
    note: str                        # why this step is in the chain


@dataclass(frozen=True, slots=True)
class Chain:
    steps: tuple[Step, ...]
    source_op: str                   # where attacker text enters
    source_field: str
    outcome: Outcome
    boundaries: tuple[str, ...]
    impact: int                      # 1..5, from the terminal effect
    plausibility: float              # 0..1, heuristic until a model scores it
    min_confidence: float            # weakest effect confidence on the path
    evidence: Evidence = Evidence.HYPOTHETICAL
    generic: bool = False            # cross-domain injected-agent reach
    entry_count: int = 1             # how many untrusted entries reach the terminal

    @property
    def chain_id(self) -> str:
        raw = "|".join(s.op_key for s in self.steps)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def length(self) -> int:
        return len(self.steps)


def _terminal_outcome(op: Operation) -> tuple[Outcome, int, float] | None:
    """Return (outcome, impact, confidence) if this op is a harmful terminal."""
    best: tuple[Outcome, int, float] | None = None
    for e in op.effects:
        out: Outcome | None = None
        impact = 3
        if e.kind in _TERMINAL:
            out = _TERMINAL[e.kind]
            impact = {Outcome.DATA_THEFT: 5, Outcome.TAKEOVER: 5,
                      Outcome.FRAUD: 5}[out]
        elif e.kind == EffectKind.DELETE and any(
                x.kind == EffectKind.IRREVERSIBLE for x in op.effects):
            out, impact = Outcome.DESTRUCTION, 4
        if out is not None and (best is None or impact > best[1]):
            best = (out, impact, e.confidence)
    return best


def _shares_object(a: Operation, b: Operation) -> bool:
    shared = (set(a.objects) & set(b.objects)) - _CONTAINER_NOUNS
    return bool(shared)


def find_chains(api: Api, *, max_depth: int = _MAX_DEPTH,
                boundaries: Boundaries | None = None) -> list[Chain]:
    links: list[WriteReadLink] = find_links(api)
    by_key = api.by_key()
    scoped = boundaries is not None and boundaries.allowed_ops is not None

    def allowed(op_key: str) -> bool:
        return boundaries.allows(op_key) if boundaries else True

    # Entry points: the reader side of a taint link (agent ingests the text).
    entries: dict[str, str] = {}   # op_key -> field that carries attacker text
    for lk in links:
        entries.setdefault(lk.reader, lk.free_text_fields[0] if lk.free_text_fields else "")

    # A boundaries file can declare untrusted fields explicitly, adding entries
    # the taint pass may have missed (e.g. data written out of band).
    if boundaries and boundaries.untrusted_fields:
        untrusted_objs = {u.split(".")[0].rstrip("s").lower()
                          for u in boundaries.untrusted_fields if "." in u}
        for op in api.operations:
            if op.objects and op.objects[-1] in untrusted_objs:
                for e in op.effects:
                    if e.kind == EffectKind.READ:
                        entries.setdefault(op.key, boundaries.untrusted_fields[0])

    # The agent can only read where it has access.
    entries = {k: v for k, v in entries.items() if allowed(k)}

    # Terminals: operations with a harmful effect the agent may actually call.
    terminals: dict[str, tuple[Outcome, int, float]] = {}
    for op in api.operations:
        t = _terminal_outcome(op)
        if t is not None and allowed(op.key):
            terminals[op.key] = t

    # Shared-object adjacency, used for same-domain data flows. Cross-domain
    # reach is handled by direct emission below. Any object shared by many
    # operations behaves like a container (e.g. "issue" across a big API) and is
    # excluded dynamically, on top of the static container list, so the graph
    # does not form huge cliques that make the search explode.
    ops = list(api.operations)
    freq: dict[str, int] = {}
    for op in ops:
        for o in set(op.objects):
            freq[o] = freq.get(o, 0) + 1
    container = _CONTAINER_NOUNS | {o for o, n in freq.items() if n > _MAX_FANOUT}

    def shares(a: Operation, b: Operation) -> bool:
        return bool((set(a.objects) & set(b.objects)) - container)

    adj: dict[str, list[Operation]] = {op.key: [] for op in ops}
    for a in ops:
        adj[a.key] = [b for b in ops if a.key != b.key and shares(a, b)]

    chains: list[Chain] = []
    seen: set[str] = set()

    def record(path: tuple[Step, ...], conf: float) -> None:
        if len(chains) >= _MAX_CHAINS:
            return
        out, impact, tconf = terminals[path[-1].op_key]
        ch = _make_chain(path, path[0].op_key, entry_field[path[0].op_key],
                         out, impact, min(conf, tconf), by_key)
        if ch.chain_id not in seen:
            seen.add(ch.chain_id)
            chains.append(ch)

    entry_field = entries
    entry_keys = list(entries)

    # 1) Cross-domain reach. An injected agent can be steered to call any
    #    privileged tool it holds. The useful unit here is the dangerous tool,
    #    not the pair, so emit ONE generic chain per terminal and note how many
    #    untrusted entries can reach it. This is where a boundaries file later
    #    narrows "any entry" to "entries the agent's role can actually touch".
    for tkey, (out, impact, tconf) in terminals.items():
        reachers = [e for e in entry_keys if e != tkey]
        if not reachers:
            continue
        rep = reachers[0]
        start = Step(rep, f"agent reads attacker text in '{entry_field[rep]}'")
        step = Step(tkey, "injected agent invokes a privileged operation")
        min_conf = min(_path_conf(by_key[rep]), tconf)
        # With a declared scope, this reach is credible, not a guess: the agent
        # really can call this tool. Treat it as a specific finding.
        ch = Chain(
            steps=(start, step), source_op=rep, source_field=entry_field[rep],
            outcome=out, boundaries=_boundaries((start, step), by_key, boundaries),
            impact=impact, plausibility=0.65 if scoped else 0.5,
            min_confidence=round(min_conf, 2),
            generic=not scoped, entry_count=len(reachers),
        )
        if ch.chain_id not in seen:
            seen.add(ch.chain_id)
            chains.append(ch)

    # 2) Same-domain specific flows: bounded DFS along shared-object edges.
    for entry_key, field_name in entries.items():
        entry_op = by_key.get(entry_key)
        if entry_op is None:
            continue
        start = Step(entry_key, f"agent reads attacker text in '{field_name}'")
        entry_conf = _path_conf(entry_op)
        stack: list[tuple[Operation, tuple[Step, ...], float]] = [
            (entry_op, (start,), entry_conf)
        ]
        while stack:
            if len(chains) >= _MAX_CHAINS:
                break
            cur, path, conf = stack.pop()
            if cur.key in terminals and len(path) >= 2:
                record(path, conf)
                continue
            if len(path) >= max_depth:
                continue
            for nxt in adj[cur.key]:
                if any(s.op_key == nxt.key for s in path):
                    continue
                step = Step(nxt.key, f"shares data with {cur.objects[-1] if cur.objects else 'prior step'}")
                stack.append((nxt, path + (step,), min(conf, _path_conf(nxt))))
    # Keep only the shortest chain to each distinct (entry, terminal, outcome):
    # a reader does not need twenty variations of the same end, just the
    # cheapest way there.
    best_by_target: dict[tuple[str, str, Outcome], Chain] = {}
    for c in chains:
        k = (c.source_op, c.steps[-1].op_key, c.outcome)
        existing = best_by_target.get(k)
        if existing is None or c.length < existing.length:
            best_by_target[k] = c
    deduped = list(best_by_target.values())
    deduped.sort(key=lambda c: (c.impact, c.plausibility, -c.length), reverse=True)
    return deduped


def _path_conf(op: Operation) -> float:
    return min((e.confidence for e in op.effects), default=1.0)


def _boundaries(steps: tuple[Step, ...], by_key: dict[str, Operation],
                boundaries: Boundaries | None = None) -> tuple[str, ...]:
    bs: list[str] = ["untrusted text drives a privileged action"]
    for s in steps:
        op = by_key.get(s.op_key)
        if op and any(e.kind == EffectKind.CHANGE_IDENTITY for e in op.effects):
            bs.append("identity change inside the chain")
            break
    if boundaries:
        if boundaries.acts_as:
            bs.append(f"acts as '{boundaries.acts_as}'")
        tp = boundaries.tenant_param
        if tp:
            terminal = by_key.get(steps[-1].op_key)
            if terminal and ("{" + tp + "}") in terminal.path:
                bs.append(f"tenant-scoped on '{tp}'; confirm no cross-tenant access")
    return tuple(dict.fromkeys(bs))


def _make_chain(path: tuple[Step, ...], entry: str, field_name: str,
                outcome: Outcome, impact: int, min_conf: float,
                by_key: dict[str, Operation]) -> Chain:
    # Plausibility: shorter chains and fewer identity switches are more likely
    # for an agent to walk. Heuristic placeholder until a model scores it.
    length_penalty = 0.15 * (len(path) - 1)
    plausibility = max(0.1, min(1.0, 0.9 - length_penalty))
    return Chain(
        steps=path, source_op=entry, source_field=field_name, outcome=outcome,
        boundaries=_boundaries(path, by_key), impact=impact,
        plausibility=round(plausibility, 2), min_confidence=round(min_conf, 2),
    )
