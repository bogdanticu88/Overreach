# Baseline comparison: independent chains vs the tool

## Method

To check the finder's recall without grading its own homework, two fresh agents
with no knowledge of this tool or its output were each given only a neutral
operation inventory of a real API (Gitea, Mattermost) and asked, as pentesters,
to list the attack chains they would expect. Each produced 20 chains
independently (`gitea_baseline_independent.md`, `mattermost_baseline_independent.md`).
The finder was then run on the same specs and matched against those baselines by
terminal operation (parameter names normalised).

This is a proxy for a human first pass, not a substitute for one; the agents
share some blind spots with the tool. Bogdan's own review is the next layer.

## Result

| Spec | Baseline chains | Recall before | Recall after |
| --- | --- | --- | --- |
| Gitea | 20 | 6/20 | 17/20 |
| Mattermost | 20 | ~12/20 | 13/20 |

"Before" is the finder as first built; "after" includes the two fixes the
baseline prompted (below).

## What the baseline exposed, and the fixes made

1. **Exfiltration by writing to a reader-visible sink was missing entirely.**
   The biggest class of misses was the agent reading private data and writing it
   into a comment, issue or message the attacker can read. The taint pass already
   finds objects that are both written and read, so the writer side of such a
   link is now treated as an exfiltration terminal. This recovered the whole
   comment-relay family (6+ chains on Gitea).
2. **Privilege and authority changes were under-modelled.** Collaborator and
   scheme grants, and ownership changes (promote, demote, transfer, rename), are
   now recognised as identity/takeover effects.

Both fixes are measured above and covered by tests.

## Remaining misses (roadmap, not hidden)

The finder still misses these, and they are the honest backlog:

| Class | Example terminal | What it needs |
| --- | --- | --- |
| Code execution / plugin install | `POST /plugins/{id}/enable` | a code-execution effect (OWASP ASI05) |
| Config tampering | `POST /config/reload`, config patch | a "weakens controls" effect |
| Trigger of an established channel | `POST .../hooks/{id}/tests`, `.../push_mirrors-sync`, workflow `dispatches` | model the trigger step, or treat the setup op (already flagged) as sufficient |
| Visibility / privacy downgrade | `PATCH /repos/{owner}/{repo}` (private→public), channel patch | field-based detection of a visibility flip |
| Session / MFA reset | `POST /users/{id}/sessions/revoke/all` | an "auth reset" effect |
| Cross-org federation | remote-cluster channel invite | model federation as an external sink |
| Member addition | `POST /channels/{id}/members` | re-admit "member" as a privilege term once noise is controlled |
| AI-recap / summary injection | `GET /recaps/{id}` | treat model-generated summaries as untrusted input |

The three Gitea misses that remain are all trigger steps whose *setup* operation
the finder does flag (create the webhook, create the mirror), so the control
point is caught even when the baseline's chosen terminal is not.

## Note on counts

Without a boundaries file the finder reports cross-domain reach from every
untrusted entry, so raw counts are high (Gitea ~400). A boundaries file scopes
these to what the agent can actually call; the recall above is measured on the
unscoped run to match the baselines, which also assume broad access.
