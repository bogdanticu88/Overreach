"""Re-score the independent Gitea/Mattermost baselines against the finder.

Criterion (explicit, applied identically everywhere): a baseline chain is
RECALLED if the finder, run with NO boundaries file (the "broad access"
assumption the baselines themselves make), emits at least one chain whose
terminal operation (path parameters normalised to `{}`) equals one of the
baseline chain's documented harmful terminal operations. Setup-only matches for
trigger chains do NOT count (mirrors the original treatment of trigger chains as
misses). This is a proxy for terminal-reachability recall, not a precision claim.
"""
from __future__ import annotations

import glob
import os
import re
import sys

sys.path.insert(0, "src")
from overreach.chains import find_chains          # noqa: E402
from overreach.infer import infer_api             # noqa: E402
from overreach.ingest import load_path, merge_docs  # noqa: E402

import yaml  # noqa: E402

# Directory holding the fetched specs (see docs/baselines/baseline_rescore.md
# for the exact sources and commits). Override with OVERREACH_SPECS.
#   <SPECS>/gitea/templates/swagger/v1-openapi3.generated.json
#   <SPECS>/mm/api/v4/source/*.yaml
SPECS = os.environ.get("OVERREACH_SPECS", "specs")


def norm(k: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", k)


# Harmful terminal operation(s) per baseline chain, from the independent
# baseline documents. Alternates ("or" in the baseline) are listed together.
GITEA = {
    "C1": ["POST /repos/{}/{}/push_mirrors-sync"],
    "C2": ["POST /users/{}/tokens", "POST /repos/{}/{}/issues/{}/comments"],
    "C3": ["POST /user/keys"],
    "C4": ["POST /user/emails"],
    "C5": ["POST /repos/{}/{}/hooks/{}/tests"],
    "C6": ["PATCH /repos/{}/{}"],
    "C7": ["POST /repos/{}/{}/transfer"],
    "C8": ["PUT /repos/{}/{}/collaborators/{}"],
    "C9": ["POST /admin/users", "PATCH /admin/users/{}"],
    "C10": ["POST /repos/{}/{}/issues/{}/comments"],
    "C11": ["POST /repos/{}/{}/issues/{}/comments"],
    "C12": ["DELETE /repos/{}/{}"],
    "C13": ["PUT /repos/{}/{}/branches/{}", "DELETE /repos/{}/{}/branch_protections/{}"],
    "C14": ["POST /repos/{}/{}/keys"],
    "C15": ["POST /repos/{}/{}/actions/workflows/{}/dispatches"],
    "C16": ["POST /repos/{}/{}/issues/{}/comments"],
    "C17": ["POST /user/applications/oauth2"],
    "C18": ["POST /orgs/{}/rename", "POST /admin/users/{}/rename"],
    "C19": ["POST /repos/migrate"],
    "C20": ["POST /repos/{}/{}/issues/{}/comments"],
}

# Mattermost harmful terminals, transcribed from mattermost_baseline_independent.md
# (chain number -> the harmful terminal op(s) that chain ends in; "or" alternates
# from the baseline are listed together).
MATTERMOST = {
    "M1": ["POST /api/v4/hooks/outgoing"],
    "M2": ["POST /api/v4/posts"],                       # paste into attacker DM
    "M3": ["GET /api/v4/files/{}/link"],                # mint public file link
    "M4": ["POST /api/v4/compliance/reports", "POST /api/v4/reports/posts",
           "POST /api/v4/reports/users/export", "GET /api/v4/exports/{}",
           "POST /api/v4/exports/{}/presign-url"],
    "M5": ["POST /api/v4/plugins/install_from_url", "POST /api/v4/plugins",
           "POST /api/v4/plugins/marketplace", "POST /api/v4/plugins/{}/enable"],
    "M6": ["POST /api/v4/posts"],                       # config secrets -> DM
    "M7": ["PUT /api/v4/config/patch", "POST /api/v4/config/reload"],
    "M8": ["PUT /api/v4/users/{}/roles", "POST /api/v4/users/{}/promote"],
    "M9": ["PUT /api/v4/roles/{}/patch", "POST /api/v4/schemes",
           "PUT /api/v4/channels/{}/scheme", "PUT /api/v4/teams/{}/scheme"],
    "M10": ["POST /api/v4/users/{}/tokens"],
    "M11": ["PUT /api/v4/users/{}/password", "PUT /api/v4/users/{}/mfa",
            "PUT /api/v4/users/{}/auth", "POST /api/v4/users/{}/sessions/revoke/all"],
    "M12": ["POST /api/v4/bots", "POST /api/v4/users/{}/tokens"],
    "M13": ["POST /api/v4/oauth/apps", "POST /api/v4/oauth/apps/{}/regen_secret"],
    "M14": ["POST /api/v4/remotecluster/accept_invite", "POST /api/v4/remotecluster",
            "POST /api/v4/remotecluster/{}/channels/{}/invite"],
    "M15": ["POST /api/v4/channels/{}/members", "POST /api/v4/teams/{}/members",
            "PUT /api/v4/channels/{}/members/{}/roles"],
    "M16": ["PUT /api/v4/channels/{}/privacy", "PUT /api/v4/channels/{}/patch"],
    "M17": ["POST /api/v4/hooks/incoming"],
    "M18": ["POST /api/v4/teams/{}/invite/email",
            "POST /api/v4/teams/{}/invite-guests/email", "POST /api/v4/email/test"],
    "M19": ["DELETE /api/v4/posts/{}", "DELETE /api/v4/channels/{}",
            "DELETE /api/v4/teams/{}", "DELETE /api/v4/users/{}", "DELETE /api/v4/users"],
    "M20": ["POST /api/v4/recaps", "POST /api/v4/recaps/{}/regenerate"],
}


def gitea_api():
    return infer_api(load_path(
        SPECS + "/gitea/templates/swagger/v1-openapi3.generated.json"))


def mattermost_api():
    docs = []
    for f in sorted(glob.glob(SPECS + "/mm/api/v4/source/*.yaml")):
        try:
            d = yaml.safe_load(open(f))
            if isinstance(d, dict):
                docs.append(d)
        except Exception:
            pass
    return infer_api(merge_docs(docs, "Mattermost", "v4"))


def score(label, api, baseline):
    ch = find_chains(api)
    terms = {norm(c.steps[-1].op_key) for c in ch}
    hits, misses = 0, []
    for cid, alts in baseline.items():
        if any(a in terms for a in alts):
            hits += 1
        else:
            misses.append(cid)
    print(f"{label}: chains={len(ch)} recall={hits}/{len(baseline)} misses={misses}")
    return hits


if __name__ == "__main__":
    score("GITEA", gitea_api(), GITEA)
    score("MATTERMOST", mattermost_api(), MATTERMOST)
