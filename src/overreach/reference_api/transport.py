"""Delivery transport for the reference API.

The reference API can register webhooks and "deliver" push payloads to them.
Making that a real outbound HTTP call turns the reference API into an SSRF and
exfiltration primitive: a caller registers http://169.254.169.254/... or an
internal address and a push reaches it. So delivery goes through a Transport,
and the default never touches the network.

- CaptureTransport (default): records deliveries in memory. No sockets, ever.
- GuardedHttpTransport (opt-in): refuses non-HTTP schemes and destinations that
  are, or resolve to, loopback / private / link-local / reserved / multicast /
  unspecified addresses, and only then sends. It is not wired by default and is
  not used by the demo or the tests.

Safety here is enforced by code, not by a comment claiming a sandbox is safe.

SSRF note: literal IPs are recognised in every form an OS accepts, including the
decimal (2130706433), hex (0x7f000001), octal and shorthand (127.1) encodings of
loopback/internal addresses, not just dotted-quad. For a bare hostname the
guarded transport resolves it ONCE, refuses if any resolved address is
non-public, and passes the single validated IP to the sender, which must connect
to that IP (not re-resolve the hostname) — this is what closes the DNS-rebinding
window; see ``GuardedHttpTransport``.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlparse

_LOCAL_NAMES = ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")


class Transport(Protocol):
    def deliver(self, destination: str, payload: dict[str, Any]) -> bool: ...
    def captured(self, destination: str) -> list[dict[str, Any]]: ...
    def reset(self) -> None: ...


_IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


def _as_ip(host: str) -> _IPAddr | None:
    """Return the IP a host literal denotes, in any encoding an OS resolver
    accepts (dotted-quad, IPv6, decimal, hex, octal, shorthand), or None for a
    genuine hostname."""
    host = host.strip("[]")                       # IPv6 URL brackets
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Integer encodings: decimal "2130706433", hex "0x7f000001", octal "0o...".
    try:
        val = int(host, 0) if host[:2].lower() in ("0x", "0o") else int(host)
        return ipaddress.ip_address(val)
    except (ValueError, TypeError):
        pass
    # Shorthand like "127.1" or "0177.0.0.1" that inet_aton still accepts.
    try:
        return ipaddress.ip_address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def _is_blocked_ip(ip: _IPAddr) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def is_blocked_destination(url: str) -> bool:
    """True if a URL must not be contacted: a non-HTTP scheme, a malformed URL,
    a local name, or a host that is a literal IP (in any encoding) in a
    loopback / private / link-local / reserved / multicast / unspecified range.
    A genuine hostname returns False here and is resolved-and-rechecked by the
    guarded transport before any request is made."""
    try:
        parsed = urlparse(url)
    except Exception:
        return True
    if parsed.scheme not in ("http", "https"):
        return True
    host = parsed.hostname
    if not host:
        return True
    if host.lower() in _LOCAL_NAMES:
        return True
    ip = _as_ip(host)
    if ip is None:
        return False          # hostname: resolved by the guarded transport
    return _is_blocked_ip(ip)


# A resolver maps a hostname to the list of IP strings it resolves to. Injected
# so the guard can be tested without real DNS.
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    try:
        return [str(ai[4][0]) for ai in socket.getaddrinfo(host, None)]
    except OSError:
        return []


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


# A pinning sender receives (url, payload, validated_ip). It MUST open its
# connection to validated_ip (with the URL's host as Host / TLS SNI) and MUST
# NOT re-resolve the hostname — that is what closes the DNS-rebinding window.
PinningSender = Callable[[str, dict[str, Any], str], None]


class GuardedHttpTransport:
    """Opt-in real delivery. Refuses blocked destinations, resolves a hostname
    once and refuses if any resolved address is non-public, then hands the sender
    the single validated IP it must connect to.

    The sender and resolver are injected so the guard can be tested without any
    network. Because the guard passes the validated IP to the sender (rather than
    only the URL), a correct sender never performs a second DNS lookup, so a
    rebinding answer at connect time cannot reach an internal address. A sender
    that ignores the pinned IP and re-resolves defeats this, which is why the
    contract requires using it.
    """

    def __init__(self, sender: PinningSender | None = None,
                 resolver: Resolver | None = None) -> None:
        self._sender = sender
        self._resolver = resolver or _default_resolver
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.pinned: list[tuple[str, str]] = []   # (url, validated ip) actually sent
        self.refused: list[str] = []

    def deliver(self, destination: str, payload: dict[str, Any]) -> bool:
        if is_blocked_destination(destination):
            self.refused.append(destination)
            return False
        host = urlparse(destination).hostname or ""
        literal = _as_ip(host)
        if literal is not None:
            pinned_ip = str(literal)       # already validated public by the guard
        else:
            # A hostname: resolve ONCE here, refuse if any resolved address is
            # non-public, and pin the connection to one validated address so the
            # sender does not resolve again (DNS rebinding).
            resolved = self._resolver(host)
            validated = [r for r in resolved
                         if (ip := _as_ip(r)) is not None and not _is_blocked_ip(ip)]
            if not resolved or len(validated) != len(resolved):
                self.refused.append(destination)
                return False
            pinned_ip = validated[0]
        if self._sender is not None:
            self._sender(destination, payload, pinned_ip)
        self.sent.append((destination, payload))
        self.pinned.append((destination, pinned_ip))
        return True

    def captured(self, destination: str) -> list[dict[str, Any]]:
        return [p for d, p in self.sent if d == destination]

    def reset(self) -> None:
        self.sent.clear()
        self.refused.clear()
