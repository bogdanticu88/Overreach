"""Opt-in reference pinning sender for GuardedHttpTransport.

This is the one piece Overreach deliberately does not wire by default: the code
that actually opens an outbound connection. It is provided as a *reference*
implementation of the pinning contract so an integrator does not have to get the
fiddly parts (TLS SNI vs. the dialed IP, redirect handling) wrong. It uses only
the standard library, adds no dependency, and is never imported by the default
transport.

Contract honoured (see ``GuardedHttpTransport``):
  1. connect to one of the ``validated_ips`` the guard passed, never re-resolve
     the hostname (that is the DNS-rebinding hole);
  2. for HTTPS, present the URL hostname as TLS SNI and the HTTP Host header, so
     certificate validation still applies even though an IP was dialed;
  3. POST the JSON payload;
  4. fail closed on a redirect: a 3xx response is refused, not followed blindly
     (its target would need re-validation through the guard first).

Usage (opt-in, never the default):

    from overreach.reference_api import set_transport
    from overreach.reference_api.transport import GuardedHttpTransport
    from overreach.reference_api.http_sender import pinning_http_sender
    set_transport(GuardedHttpTransport(sender=pinning_http_sender))
"""
from __future__ import annotations

import json
import socket
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

# A low-level perform: open a pinned connection to ``ip`` presenting ``host``,
# POST ``body`` to ``path``, and return (status_code, location_header_or_None).
# Injected so the sender can be tested without a real socket.
Perform = Callable[..., tuple[int, str | None]]


class RedirectRefused(Exception):
    """A redirect response was received and refused (fail closed)."""


class PinnedDeliveryError(Exception):
    """The pinned request could not be completed."""


def _host_header(host: str, port: int, scheme: str) -> str:
    """The HTTP Host header value: hostname alone on the scheme's default port,
    hostname:port otherwise (RFC 7230), so a webhook on a custom port routes."""
    default = 443 if scheme == "https" else 80
    return host if port == default else f"{host}:{port}"


def _default_perform(ip: str, host: str, port: int, scheme: str,
                     path: str, body: bytes, timeout: float) -> tuple[int, str | None]:
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        if scheme == "https":
            # SNI and certificate validation use the hostname, not the dialed IP
            # and not the port.
            ctx = ssl.create_default_context()
            sock: socket.socket = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {_host_header(host, port, scheme)}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body
        sock.sendall(request)
        with sock.makefile("rb") as fp:
            status_line = fp.readline().decode("latin1", "replace").strip()
            parts = status_line.split(" ", 2)
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            location: str | None = None
            while True:
                line = fp.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if line.lower().startswith(b"location:"):
                    location = line.split(b":", 1)[1].strip().decode("latin1", "replace")
        return status, location
    finally:
        raw.close()


def pinning_http_sender(url: str, payload: dict[str, Any], validated_ips: list[str],
                        *, timeout: float = 5.0, _perform: Perform | None = None) -> None:
    """Deliver ``payload`` to ``url``, pinned to the guard's validated IPs.

    Raises ``PinnedDeliveryError`` if no validated IP is available or the request
    fails, and ``RedirectRefused`` on any redirect response (which must be
    re-validated through the guard before being followed).
    """
    if not validated_ips:
        raise PinnedDeliveryError("no validated IP to connect to")
    perform = _perform or _default_perform
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    if scheme not in ("http", "https") or not host:
        raise PinnedDeliveryError(f"unsupported destination: {url!r}")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    body = json.dumps(payload).encode("utf-8")

    status, location = perform(validated_ips[0], host, port, scheme, path, body, timeout)
    if 300 <= status < 400:
        raise RedirectRefused(
            f"refused redirect to {location!r}: a redirect target must be "
            "re-validated through the guard before being followed")
    if status >= 400 or status == 0:
        raise PinnedDeliveryError(f"delivery to {url!r} returned status {status}")
