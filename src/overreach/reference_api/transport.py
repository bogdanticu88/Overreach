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
guarded transport resolves it and refuses if ANY resolved address is non-public.
Full protection against DNS-rebinding also requires the injected sender to open
the connection to the validated address the guard returns, rather than
re-resolving the hostname itself; see ``GuardedHttpTransport``.
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


class GuardedHttpTransport:
    """Opt-in real delivery. Refuses blocked destinations, resolves hostnames and
    refuses if any resolved address is non-public, then sends.

    The sender and resolver are injected so the guard can be tested without any
    network. The sender receives the destination URL; for full DNS-rebinding
    safety it should connect to the validated address rather than re-resolving
    the hostname (the guard has already confirmed every resolved address is
    public, but a later lookup could differ).
    """

    def __init__(self, sender: Callable[[str, dict[str, Any]], None] | None = None,
                 resolver: Resolver | None = None) -> None:
        self._sender = sender
        self._resolver = resolver or _default_resolver
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.refused: list[str] = []

    def deliver(self, destination: str, payload: dict[str, Any]) -> bool:
        if is_blocked_destination(destination):
            self.refused.append(destination)
            return False
        host = urlparse(destination).hostname or ""
        if _as_ip(host) is None:
            # A hostname: resolve and refuse if ANY resolved address is non-public
            # (a hostname pointing at an internal IP, or a mixed answer).
            resolved = self._resolver(host)
            if not resolved or any(
                    (ip := _as_ip(r)) is None or _is_blocked_ip(ip) for r in resolved):
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
