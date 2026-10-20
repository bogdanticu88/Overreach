"""A deliberately vulnerable reference API.

It is written to look clean: every operation has an id, summary, description,
tags and declared bearer auth, so agent-readiness linters score it well. The
danger is emergent, in how legitimate operations combine. Two chains are
planted: data exfiltration via a webhook, and account takeover via email change
plus password reset.

The attacker-controlled destination is observed through the delivery transport's
capture log (see ``transport.py`` and ``overreach.replay``), which never opens a
socket, rather than through any network-facing endpoint.
"""
from overreach.reference_api.app import (
    app,
    get_state,
    get_transport,
    reset_state,
    set_transport,
)

__all__ = ["app", "get_state", "get_transport", "reset_state", "set_transport"]
