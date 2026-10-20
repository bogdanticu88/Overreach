"""The reference API must not make real outbound requests, and any opt-in real
transport must refuse unsafe destinations (SSRF)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from overreach.reference_api import app, get_transport, reset_state
from overreach.reference_api.transport import (
    CaptureTransport,
    GuardedHttpTransport,
    is_blocked_destination,
)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x",
    "http://localhost/x",
    "https://localhost:8443/x",
    "http://[::1]/x",
    "http://10.0.0.5/x",
    "http://172.16.0.1/x",
    "http://192.168.1.1/x",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://0.0.0.0/x",
    "ftp://example.com/x",                         # non-HTTP scheme
    "file:///etc/passwd",
    "javascript:alert(1)",
    "not a url",
    "",
    # Loopback / internal in non-dotted-quad encodings (SSRF bypass classes).
    "http://2130706433/latest",                    # decimal 127.0.0.1
    "http://0x7f000001/x",                         # hex 127.0.0.1
    "http://0177.0.0.1/x",                          # octal first octet
    "http://127.1/x",                               # shorthand 127.0.0.1
    "http://[0:0:0:0:0:0:0:1]/x",                   # expanded IPv6 loopback
])
def test_blocked_destinations(url):
    assert is_blocked_destination(url) is True


@pytest.mark.parametrize("url", [
    "http://example.com/hook",
    "https://hooks.example.org/path?x=1",
])
def test_public_destinations_allowed(url):
    assert is_blocked_destination(url) is False


def test_default_transport_is_offline_and_never_sends():
    reset_state()
    assert isinstance(get_transport(), CaptureTransport)
    client = TestClient(app)
    owner, repo = "acme", "r"
    # Register a webhook at an internal address and trigger a push.
    client.post(f"/repos/{owner}/{repo}/hooks",
                json={"url": "http://169.254.169.254/steal", "events": ["push"]})
    resp = client.post(f"/repos/{owner}/{repo}/push")
    # It is "delivered" only to the in-memory capture log, not the network.
    assert resp.json()["delivered"] == 1
    assert get_transport().captured("http://169.254.169.254/steal")


def test_guarded_transport_refuses_unsafe_and_makes_no_call():
    calls: list[str] = []
    t = GuardedHttpTransport(sender=lambda dest, payload: calls.append(dest))
    assert t.deliver("http://169.254.169.254/x", {"a": 1}) is False
    assert t.deliver("http://10.0.0.1/x", {"a": 1}) is False
    assert t.deliver("http://2130706433/x", {"a": 1}) is False   # decimal loopback
    assert calls == []            # nothing was sent
    assert t.refused == ["http://169.254.169.254/x", "http://10.0.0.1/x",
                         "http://2130706433/x"]


def test_guarded_transport_sends_only_to_public():
    # Inject a resolver so the test does no real DNS; example.com -> a public IP.
    calls: list[tuple[str, dict]] = []
    t = GuardedHttpTransport(sender=lambda dest, payload: calls.append((dest, payload)),
                             resolver=lambda host: ["93.184.216.34"])
    assert t.deliver("https://example.com/hook", {"ok": True}) is True
    assert calls == [("https://example.com/hook", {"ok": True})]


def test_guarded_transport_refuses_hostname_resolving_to_internal():
    # A hostname whose A record points at an internal address must be refused
    # (DNS-based SSRF), even though the literal check could not catch it.
    calls: list[str] = []
    t = GuardedHttpTransport(sender=lambda dest, payload: calls.append(dest),
                             resolver=lambda host: ["10.0.0.7"])
    assert t.deliver("https://sneaky.internal.example/x", {"a": 1}) is False
    assert calls == []
    assert t.refused == ["https://sneaky.internal.example/x"]


def test_guarded_transport_refuses_when_any_resolved_ip_is_internal():
    # A mixed answer (one public, one internal) is refused.
    t = GuardedHttpTransport(sender=lambda d, p: None,
                             resolver=lambda host: ["93.184.216.34", "127.0.0.1"])
    assert t.deliver("https://mixed.example/x", {"a": 1}) is False
