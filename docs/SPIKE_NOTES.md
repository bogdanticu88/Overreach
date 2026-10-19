# Feasibility spike notes

Date: 2026-10-19. Targets: Gitea and Mattermost, current OpenAPI specs pulled
from each project's main repository. Both run locally; no hosted instance was
touched. These are engineering notes, not a published report.

## Question

Can meaningful attack chains be found automatically in a real, unfamiliar
OpenAPI spec, without hand-coding each API's business rules?

## Result: yes, with caveats

The engine parses both specs, infers effects, pairs taint, and produces chains
in under a second to a couple of seconds. It also validates two planted chains
end to end on the bundled reference API by executing them and watching a canary
leave.

| Spec | Operations | Findings | Specific | Generic | Time |
| --- | --- | --- | --- | --- | --- |
| Gitea | 537 | 253 | 115 | 138 | ~0.5 s |
| Mattermost | 604 | 356 | 203 | 153 | ~2 s |

"Specific" chains are multi-step flows along a shared data object. "Generic"
findings are one per dangerous tool reachable from untrusted input; an injected
agent could be steered to any tool it holds, so these are summarised per tool,
not per entry-tool pair.

## What the spike caught and fixed

Running on real specs immediately exposed problems that a tidy fixture hid:

1. **Container nouns create false links and cliques.** Pairing taint or
   adjacency on broad nouns like `repo`, `org` or `user` linked almost every
   operation to every other, producing 11,000+ spurious write-read links and a
   ~77-node clique that made the search explode. Fixed by pairing on the
   specific resource (the last path noun) and excluding both a static container
   list and any object shared by more than a dozen operations.
2. **The cross-product blew up the report.** Emitting every (entry, terminal)
   pair produced ~4,000 near-identical findings. Collapsed to one finding per
   dangerous tool, with a count of how many untrusted entries reach it.
3. **Mattermost paths sit at the top level**, not under `paths:`. The merge step
   now handles both layouts.
4. **Lexical effect guesses are noisy.** `move_money` fires on words like
   "order" and "transfer" even on APIs with no payments (15 such findings on
   each of Gitea and Mattermost). These carry low confidence (0.5) and need the
   model pass, or a boundaries file, to settle. Left visible on purpose.

## Honest limitations (v0.1)

- Without a boundaries file, generic reach assumes an agent can call any tool.
  Real value needs the caller's scope, which the boundaries file will carry.
- Effects are inferred, not observed. Every one is tagged `inferred` with a
  confidence; none should be read as ground truth about the running system.
- Validation runs only against the bundled reference API, where we own the
  implementation. Chains found in Gitea or Mattermost are `hypothetical` until
  someone validates them against an authorised instance.
- Plausibility is a length heuristic, not a model judgement yet.

## Next

- Boundaries file, to turn generic reach into scoped, specific chains.
- Model pass for low-confidence effects, measured against these same specs.
- A hand-written chain baseline for Gitea and Mattermost, written before
  looking at tool output, as the independent precision check.
