"""
URL transport-security helpers.

SECREM-01 WEB-4 (pre-audit 2026-06-09): the SDK's RPC and IPFS clients default
to ``http://localhost`` endpoints. A localhost ``http://`` endpoint is fine —
the traffic never leaves the machine. But when a user points a client at a
*remote* host over plain ``http://``, RPC payloads (which can carry signed
transactions, private inputs, and CIDs) and IPFS traffic cross the network in
cleartext, exposed to interception and tampering.

This module centralises the policy: remote ``http://`` is warned about by
default, with an explicit opt-out for the rare operator who genuinely needs
plaintext to a remote host (e.g. an internal lab network without TLS).
"""

import ipaddress
import warnings
from urllib.parse import urlparse

# Hostnames that are always local to the calling machine — plaintext to these
# never traverses an untrusted network, so http:// is silently allowed.
_LOCAL_HOSTNAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def _is_local_host(host: str) -> bool:
    """True if ``host`` resolves to a loopback/local address by name or literal."""
    if not host:
        return False
    h = host.lower()
    if h in _LOCAL_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        # Not an IP literal and not a known local hostname.
        return False


def enforce_transport_security(url: str, *, allow_insecure_http: bool = False) -> str:
    """
    Validate the transport security of ``url`` and return it unchanged.

    - ``https://`` URLs pass silently.
    - ``http://`` to a loopback/localhost host passes silently (local traffic).
    - ``http://`` to a *remote* host emits a :class:`UserWarning` unless
      ``allow_insecure_http=True`` is passed, in which case it passes silently.

    The URL is returned as-is (we never rewrite the scheme implicitly — an
    automatic http→https upgrade to a host that doesn't serve TLS would fail
    confusingly; warning keeps the user in control). Callers that want a hard
    failure can raise on the warning via ``warnings.simplefilter("error")``.
    """
    if not isinstance(url, str) or not url:
        return url

    parsed = urlparse(url)
    if parsed.scheme != "http":
        # https, or a non-http scheme we don't police here.
        return url

    if _is_local_host(parsed.hostname or ""):
        return url

    if not allow_insecure_http:
        warnings.warn(
            f"Connecting to remote host {parsed.hostname!r} over plaintext "
            f"http:// ({url!r}). Traffic (including signed transactions and "
            f"private inputs) is sent in cleartext and can be intercepted or "
            f"tampered with. Use an https:// endpoint, or pass "
            f"allow_insecure_http=True to silence this warning if you really "
            f"intend to use http to a remote host.",
            UserWarning,
            stacklevel=3,
        )
    return url
