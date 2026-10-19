"""A deliberately vulnerable reference API.

It is written to look clean: every operation has an id, summary, description,
tags and declared bearer auth, so agent-readiness linters score it well. The
danger is emergent, in how legitimate operations combine. Two chains are
planted: data exfiltration via a webhook, and account takeover via email change
plus password reset.

Attacker-receiver endpoints (prefixed ``/_sink``) are excluded from the public
OpenAPI schema; they stand in for an endpoint the attacker controls, used only
so the validation harness can observe exfiltration.
"""
from apd.reference_api.app import app, get_state, reset_state

__all__ = ["app", "get_state", "reset_state"]
