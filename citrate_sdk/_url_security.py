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
import unicodedata
from urllib.parse import urlparse

# PBA-L6b-026: only these schemes are ever accepted.
_ALLOWED_SCHEMES = frozenset({"https", "http"})

# Hostnames that are always local to the calling machine — plaintext to these
# never traverses an untrusted network, so http:// is silently allowed.
_LOCAL_HOSTNAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


class InsecureTransportError(ValueError):
    """Raised when a remote endpoint would be reached over plaintext http://.

    SPY-B-009: the asset being protected is signed transactions, private model
    inputs, and bearer credentials (gateway keys, OIDC id/access/refresh tokens).
    For that asset class the control FAILS CLOSED — a remote ``http://`` endpoint
    raises unless the caller explicitly passes ``allow_insecure_http=True``.
    """


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

    - Anything but ``https``/``http``, an empty scheme or host, and any URL
      containing whitespace or control characters RAISES (PBA-L6b-026).
    - ``https://`` URLs pass silently.
    - ``http://`` to a loopback/localhost host passes silently (local traffic).
    - ``http://`` to a *remote* host RAISES :class:`InsecureTransportError`
      unless ``allow_insecure_http=True`` is passed, in which case it passes
      silently.

    SPY-B-009: this used to WARN and proceed. A ``UserWarning`` is shown once per
    location by default and is routinely suppressed by libraries and frameworks,
    so plaintext transport of signed transactions, private inputs, and bearer
    credentials went out with no effective signal. The default now FAILS CLOSED:
    the caller must opt in to remote plaintext, which is exactly what the
    ``allow_insecure_http`` flag was designed for. The scheme is never rewritten
    implicitly — an automatic http→https upgrade to a host that doesn't serve TLS
    would fail confusingly.
    """
    # PBA-L6b-026: this used to return non-strings, empty strings and any URL
    # whose parsed scheme was not "http" unchecked. "\u00a0http://remote"
    # parses with an EMPTY scheme, so it passed; requests then strips the
    # whitespace and sends plaintext to the remote host. Now: refuse
    # whitespace/control/format characters anywhere (they have no business in
    # an endpoint URL and different parsers treat them differently), allow
    # only https/http, and refuse an empty scheme or host.
    if not isinstance(url, str) or not url:
        raise InsecureTransportError(f"Refusing an empty or non-string endpoint URL: {url!r}")
    for ch in url:
        if ch.isspace() or unicodedata.category(ch)[0] in ("C", "Z"):
            raise InsecureTransportError(
                f"Refusing endpoint URL {url!r}: it contains whitespace or a control "
                f"character (U+{ord(ch):04X}). Parsers disagree on such URLs, which "
                "lets an http:// endpoint slip past this check (PBA-L6b-026)."
            )

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InsecureTransportError(
            f"Refusing endpoint URL {url!r}: scheme {parsed.scheme!r} is not https or "
            "http (PBA-L6b-026)."
        )
    if not parsed.hostname:
        raise InsecureTransportError(f"Refusing endpoint URL {url!r}: no host (PBA-L6b-026).")
    if scheme == "https":
        return url

    if _is_local_host(parsed.hostname):
        return url

    if not allow_insecure_http:
        raise InsecureTransportError(
            f"Refusing to connect to remote host {parsed.hostname!r} over "
            f"plaintext http:// ({url!r}). Traffic (including signed "
            f"transactions, private inputs, and bearer credentials) would be "
            f"sent in cleartext and could be intercepted or tampered with. Use "
            f"an https:// endpoint, or pass allow_insecure_http=True to opt in "
            f"if you really intend to use http to a remote host."
        )
    return url
