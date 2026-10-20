"""Regression tests for the three false-positive classes fixed before v0.1:

1. sink-writer exfil only on communication-surface objects;
2. transfer/rename as takeover only on an ownable object;
3. provider / redirect / subject-attribute URLs and emails are not egress.
"""
from __future__ import annotations

import json

from overreach.chains import Outcome, find_chains
from overreach.infer import infer_api, infer_operation
from overreach.ingest import _is_exit_field, load_text
from overreach.model import EffectKind, Operation


def _spec(paths: dict) -> str:
    return json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
                       "paths": paths})


def _body(props: dict) -> dict:
    return {"requestBody": {"content": {"application/json": {
        "schema": {"type": "object", "properties": props}}}}}


# --- Fix 3: egress vs non-egress URL/email fields --------------------------

def test_genuine_egress_fields_are_exits():
    for name in ["url", "webhook_url", "callback", "callback_url", "endpoint",
                 "destination", "notify_email", "email"]:
        assert _is_exit_field(name, {}) is True, name


def test_provider_and_redirect_urls_are_not_exits():
    for name in ["oauth_authorize_url", "oauth_token_url", "return_url",
                 "redirect_uri", "success_url", "cancel_url", "issuer",
                 "jwks_uri", "privacy_policy_url", "terms_of_service_url"]:
        assert _is_exit_field(name, {"format": "uri"}) is False, name


def test_subject_email_attributes_are_not_exits():
    for name in ["customer_email_address", "billing_email", "owner_email",
                 "sender_email", "contact_email"]:
        assert _is_exit_field(name, {"format": "email"}) is False, name


# --- Fix 2: transfer/rename only takeover on an ownable object -------------

def _op(method: str, path: str) -> Operation:
    return infer_operation(Operation(op_id="x", method=method, path=path))


def test_ownership_transfer_is_identity_change():
    for path in ["/repos/{owner}/{repo}/transfer", "/orgs/{org}/rename",
                 "/projects/{id}/transfer"]:
        op = _op("post", path)
        assert any(e.kind == EffectKind.CHANGE_IDENTITY for e in op.effects), path


def test_non_ownership_transfer_is_not_identity_change():
    # A workspace/file transfer or a label rename is not account takeover.
    for path in ["/agents/sessions/{id}/workspace/transfers",
                 "/channels/{id}/files/transfer", "/labels/{id}/rename"]:
        op = _op("post", path)
        assert not any(e.kind == EffectKind.CHANGE_IDENTITY for e in op.effects), path


def test_credential_and_oauth_addition_is_identity_change():
    for path in ["/user/keys", "/repos/{owner}/{repo}/keys",
                 "/user/applications/oauth2"]:
        op = _op("post", path)
        assert any(e.kind == EffectKind.CHANGE_IDENTITY for e in op.effects), path


# --- Fix 1: sink-writer exfil only on communication surfaces ---------------

def test_communication_sink_is_an_exfil_terminal():
    api = infer_api(load_text(_spec({
        "/comments": {
            "post": {"operationId": "addComment", **_body({"body": {"type": "string"}})},
            "get": {"operationId": "listComments"},
        },
    })))
    chains = find_chains(api)
    assert any(c.outcome == Outcome.DATA_THEFT
               and c.steps[-1].op_key == "POST /comments" for c in chains)


def test_same_domain_config_create_is_not_an_exfil_terminal():
    # Writing a config object's description that the same reader reads back is
    # not exfiltration; it must not become a sink-writer terminal.
    api = infer_api(load_text(_spec({
        "/toolbelts": {
            "post": {"operationId": "createToolbelt",
                     **_body({"description": {"type": "string"}})},
            "get": {"operationId": "listToolbelts"},
        },
    })))
    chains = find_chains(api)
    assert not any(c.steps[-1].op_key == "POST /toolbelts" for c in chains)
