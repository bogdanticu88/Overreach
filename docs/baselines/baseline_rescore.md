# Baseline re-score on current code

This re-runs the independent Gitea and Mattermost baselines
(`gitea_baseline_independent.md`, `mattermost_baseline_independent.md`) against
the current finder, after the Phase-1 precision tuning, and investigates the
effect of those changes on recall. The original comparison (`comparison.md`)
reported Gitea 17/20 and Mattermost 13/20 from an ad-hoc process; no scoring
script was committed, so this introduces a transparent, reproducible one.

## Method

`docs/baselines/rescore.py` is the scorer. Criterion, applied identically to
every chain: a baseline chain is **recalled** if the finder, run with **no
boundaries file** (the broad-access assumption the baselines make), emits at
least one chain whose terminal operation (path parameters normalised to `{}`)
equals one of that baseline chain's documented harmful terminal operations.
Trigger chains whose only match is a setup operation do **not** count. This
measures terminal-reachability recall, not precision.

The per-chain terminal maps are transcribed from the two baseline documents and
are in the scorer, so the scoring is auditable rather than asserted.

### Sources (reproducible)

| Spec | Source | Commit | Path |
|---|---|---|---|
| Gitea | github.com/go-gitea/gitea | sparse `templates/swagger` | `templates/swagger/v1-openapi3.generated.json` (OpenAPI 3.0.3, 537 ops) |
| Mattermost | github.com/mattermost/mattermost | sparse `api` | `api/v4/source/*.yaml`, merged with `overreach.ingest.merge_docs` (604 ops) |

Run with `OVERREACH_SPECS=<dir> python -I docs/baselines/rescore.py` from the
repo root.

## Regression investigation

The scorer was run at three commits to isolate the effect of each Phase-1
change:

| Commit | What it is | Gitea | Mattermost |
|---|---|---|---|
| `073cfbf` | before the Phase-1 finder changes | 8/20 | 17/20 |
| `41920a7` | after the lazy `$ref` resolver, before the taint change | **17/20** | 17/20 |
| `5bf8356` (HEAD) | after the taint change **and** the credential-key fix | **17/20** | 15/20 |

Two effects, both real:

1. **The lazy `$ref` resolver raised Gitea recall from 8/20 to 17/20.** Gitea's
   spec is large and densely referenced; the old document-wide resolution budget
   starved it (the same blocker found on Stripe), so most request bodies — and
   thus most taint entries and sink terminals — were empty. Resolving lazily per
   operation recovered them.
2. **The taint change (dropping `name`/`title`/`subject`) caused a measured
   regression**, 17/20 -> 15/20 on Gitea (lost C3, C14) and 17/20 -> 15/20 on
   Mattermost (lost M14, M20) at the intermediate state.

### Were the lost matches genuine?

No. At `41920a7`, `POST /user/keys` and `POST /repos/{owner}/{repo}/keys` (C3,
C14) were **not** harmful terminals in their own right — their only effect was
`write`. They were counted as hits because their `title` field (a free-text hint
at the time) made them look like exfiltration **sink-writers**. That is a
coincidental classification, not detection of key addition. Removing the noisy
hint correctly removed it. The same mechanism explains the Mattermost M14
(remote-cluster federation) and M20 (AI recap) matches — both of which
`comparison.md` already lists as roadmap **misses**, i.e. threat classes the
finder does not model.

### Fix applied

Rather than restore the noisy hint, adding credential/key material is now modelled
as a persistent-access (takeover) effect (commit `5bf8356`): a non-GET operation
whose path-object noun is `key` / `gpg_key` / `ssh_key` / `deploy_key` /
`credential` / `secret` carries `CHANGE_IDENTITY`. This restores Gitea to 17/20
**for the right reason** — C3 and C14 are now genuine takeover findings — while
the Petstore control stays at 0 chains and Stripe is unchanged.

## Current recall (HEAD `5bf8356`)

- **Gitea: 17/20.** Misses C1, C5, C15 — all three are trigger chains
  (`push_mirrors-sync`, `hooks/{id}/tests`, `workflows/{id}/dispatches`) whose
  *setup* operation the finder does flag. This exactly matches the original
  `comparison.md` result and its three documented misses.
- **Mattermost: 15/20.** Misses M3 (public file link), M4 (compliance/export),
  M14 (remote-cluster federation), M16 (channel privacy patch), M20 (AI recap).
  M5/M14/M20 and the config/plugin families are the roadmap classes in
  `comparison.md`.

## Note on the Mattermost figure

This scorer reports Mattermost at 15/20, above the originally reported 13/20. The
original terminal map was not committed, so this is a reconstruction; it is more
generous on a few chains. Two of the chains it still counts as reachable (M14
federation, M20 recap) are roadmap misses that the finder does not genuinely
model, and should be read as coincidental terminal matches rather than real
detections. The honest reading is: **Gitea recall is reproduced exactly (17/20);
the Mattermost figure is in the 13–15/20 range depending on terminal-map
strictness, with federation, plugin-install, config-tampering, public-link,
compliance-export and recap-injection remaining genuine gaps.**

No labels were changed and no criteria were weakened to reach these numbers; the
scorer and maps are committed for inspection.
