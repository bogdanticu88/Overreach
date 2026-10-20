"""Delivery transport for the reference API.

The reference API can register webhooks and "deliver" push payloads to them.
Making that a real outbound HTTP call turns the reference API into an SSRF and
exfiltration primitive: a caller registers http://169.254.169.254/... or an
internal address and a push reaches it. So delivery goes through a Transport,
and the default never touches the network.

- CaptureTransport (default): records deliveries in memory. No sockets, ever.
- GuardedHttpTransport (opt-in): refuses loopback, private, link-local,
  reserved, multicast and non-HTTP destinations, and only then sends. It is not
  wired by default and is not used by the demo or the tests.

Safety here is enforced by code, not by a comment claiming a sandbox is safe.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlparse


class Transport(Protocol):
    def deliver(self, destination: str, payload: dict[str, Any]) -> bool: ...
    def captured(self, destination: str) -> list[dict[str, Any]]: ...
    def reset(self) -> None: ...


class CaptureTransport:
    """Offline-safe default: record deliveries, never open a socket."""

    def __init__(self) -> None:
        self._log: dict[str, list[dict[str, Any]]] = {}

    def deliver(self, destination: str, payload: dict[str, Any]) -> bool:
        self._log.setdefault(destination, []).append(payload)
        return True

    def captured(self, destination: str) -> list[dict[str, Any]]:
        return list(self._log.get(destination, []))

    def reset(self) -> None:
        self._log.clear()


def is_blocked_destination(url: str) -> bool:
    """True if a URL must not be contacted: a non-HTTP scheme, a malformed URL,
    or a host that resolves to a loopback, private, link-local, reserved,
    multicast or unspecified address. Literal IPs are checked directly; bare
    hostnames are left for the guarded transport to resolve and re-check, except
    obvious local names which are blocked here."""
    try:
        parsed = urlparse(url)
    except Exception:
        return True
    if parsed.scheme not in ("http", "https"):
        return True
    host = parsed.hostname
    if not host:
        return True
    if host.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A hostname, not a literal IP. We do not resolve here (that is a network
        # action); the guarded transport resolves and re-checks before sending.
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


class GuardedHttpTransport:
    """Opt-in real delivery. Refuses blocked destinations, then sends.

    The sender is injected so the guard can be tested without any network, and
    so resolution-and-recheck can be added without changing callers.
    """

    def __init__(self, sender: Callable[[str, dict[str, Any]], None] | None = None) -> None:
        self._sender = sender
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.refused: list[str] = []

    def deliver(self, destination: str, payload: dict[str, Any]) -> bool:
        if is_blocked_destination(destination):
            self.refused.append(destination)
            return False
        if self._sender is not None:
            self._sender(destination, payload)
        self.sent.append((destination, payload))
        return True

    def captured(self, destination: str) -> list[dict[str, Any]]:
        return [p for d, p in self.sent if d == destination]

    def reset(self) -> None:
        self.sent.clear()
        self.refused.clear()
