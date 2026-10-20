"""The opt-in reference pinning sender honours the guard's contract: it connects
to a validated IP, POSTs to the right path with the hostname preserved, and fails
closed on redirects. No real network is used (the low-level perform is injected).
"""
from __future__ import annotations

import pytest

from overreach.reference_api.http_sender import (
    PinnedDeliveryError,
    RedirectRefused,
    _host_header,
    pinning_http_sender,
)
from overreach.reference_api.transport import GuardedHttpTransport


def _recording_perform(record):
    def perform(ip, host, port, scheme, path, body, timeout):
        record.update(ip=ip, host=host, port=port, scheme=scheme, path=path,
                      body=body, timeout=timeout)
        return 200, None
    return perform


def test_sender_connects_to_the_validated_ip_and_preserves_host():
    rec: dict = {}
    pinning_http_sender(
        "https://hooks.example.org/path?x=1", {"event": "push"},
        ["93.184.216.34"], _perform=_recording_perform(rec))
    assert rec["ip"] == "93.184.216.34"      # dialed the validated IP ...
    assert rec["host"] == "hooks.example.org"  # ... but presents the hostname
    assert rec["port"] == 443 and rec["scheme"] == "https"
    assert rec["path"] == "/path?x=1"
    assert b'"event"' in rec["body"]


def test_sender_fails_closed_without_a_validated_ip():
    with pytest.raises(PinnedDeliveryError):
        pinning_http_sender("https://x.example/h", {}, [],
                            _perform=lambda *a: (200, None))


def test_sender_refuses_redirects():
    def redirecting(ip, host, port, scheme, path, body, timeout):
        return 302, "http://169.254.169.254/latest"
    with pytest.raises(RedirectRefused):
        pinning_http_sender("https://x.example/h", {}, ["93.184.216.34"],
                            _perform=redirecting)


def test_sender_raises_on_error_status():
    with pytest.raises(PinnedDeliveryError):
        pinning_http_sender("https://x.example/h", {}, ["93.184.216.34"],
                            _perform=lambda *a: (500, None))


def test_wired_through_guarded_transport_end_to_end():
    # The guard validates and pins; the sender connects to the pinned IP. A fake
    # perform stands in for the socket, so no real request is made.
    seen: dict = {}

    def sender(url, payload, ips):
        pinning_http_sender(url, payload, ips, _perform=_recording_perform(seen))

    t = GuardedHttpTransport(sender=sender, resolver=lambda host: ["93.184.216.34"])
    assert t.deliver("https://hooks.example.org/ci", {"ok": True}) is True
    assert seen["ip"] == "93.184.216.34"
    assert seen["host"] == "hooks.example.org"


def test_host_header_includes_non_default_port():
    # Default ports are omitted; a custom port must appear in the Host header so
    # a webhook on that port routes correctly.
    assert _host_header("h.example", 443, "https") == "h.example"
    assert _host_header("h.example", 80, "http") == "h.example"
    assert _host_header("h.example", 8443, "https") == "h.example:8443"
    assert _host_header("h.example", 8080, "http") == "h.example:8080"


def test_sender_passes_custom_port_through():
    rec: dict = {}
    pinning_http_sender(
        "https://hooks.example.org:8443/ci", {"ok": True},
        ["93.184.216.34"], _perform=_recording_perform(rec))
    assert rec["port"] == 8443 and rec["host"] == "hooks.example.org"


def test_default_perform_is_present():
    # The real socket-based perform exists and is callable (not invoked here).
    from overreach.reference_api.http_sender import _default_perform
    assert callable(_default_perform)
