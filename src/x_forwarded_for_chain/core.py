"""Parse and interpret the X-Forwarded-For header chain.

Design decisions (stated plainly so callers know what they get):

1. Header form is comma-separated. Surrounding ASCII whitespace around each
   token is stripped. Empty tokens after trimming are dropped. Non-ASCII
   whitespace is left untouched (a token containing it will be rejected by
   the IPv4/IPv6 validators rather than silently trimmed).
2. The FIRST entry in the parsed list is treated as the DIRECT address (the
   peer that connected to our server). Later entries are addresses claimed by
   proxies. This is the reverse of the chain document order (client first,
   proxy last), but the chain is appended right-to-left, so the last entry
   is the nearest hop. I picked this because it is what callers almost
   always want: "who is talking to me right now."
3. Trusted-proxy filtering walks from the nearest hop leftward until it meets
   an address NOT in the trusted set, and returns that address. If every hop
   is trusted, returns the leftmost (earliest) trusted address. If the list
   is empty, returns None. The value returned is the most specific address
   we can still trust the provenance of.
4. "Trusted" means an exact string match. No CIDR support. CIDR matching is
   useful but pulls in a lot of edge cases (is ::1 inside ::1/128? what about
   leading-zero IPv4 octets?). Out of scope here. Use exact addresses.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Sequence


def parse_x_forwarded_for(header: object) -> List[str]:
    """Split an X-Forwarded-For header into a list of address strings.

    Accepts None, an empty string, or a non-string (returns []). Accepts a
    header value containing zero or more comma-separated tokens.

    Whitespace handling: standard CRLF/SP tabs and spaces around tokens are
    trimmed; empty tokens are removed; duplicate removal is NOT performed.
    Order is preserved.

    Values are returned as raw strings. No validation is applied here so
    callers can inspect malformed input without losing information.
    """
    if header is None:
        return []
    if not isinstance(header, str):
        return []
    if header == "":
        return []

    parts: List[str] = []
    for raw in header.split(","):
        token = raw.strip()
        if token:
            parts.append(token)
    return parts


def _is_valid_ip(token: str) -> bool:
    """True iff token parses as an IPv4 or IPv6 address (per stdlib).

    ipaddress.address_str (the underlying parser) accepts v6-mapped v4 with
    the dotted form, leading-zero decimal octets with up to four chars,
    etc. We delegate to it verbatim rather than second-guessing; the stdlib
    is the source of truth.
    """
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


class XForwardedForChain:
    """Interpreted view of an X-Forwarded-For header.

    Construct once, query many times. Construction parses the header and
    validates each token; validation results are cached so the direct address,
    proxy list, and trusted filter all use the same parse.
    """

    __slots__ = ("_tokens", "_validities")

    def __init__(self, header: object) -> None:
        self._tokens: List[str] = parse_x_forwarded_for(header)
        self._validities: List[bool] = [t for t in (None,)] and []
        self._validities = [_is_valid_ip(t) for t in self._tokens]

    @property
    def tokens(self) -> List[str]:
        """Raw parsed tokens, in header order (leftmost = nearest hop)."""
        return list(self._tokens)

    @property
    def direct_address(self) -> Optional[str]:
        """The nearest hop. The first valid IP token; None if list is empty.

        Note: per the design statement, this is the FIRST token, not the
        last. The header chain is appended right-to-left, so the leftmost
        token is the address that directly connected to us.
        """
        if not self._tokens:
            return None
        return self._tokens[0]

    @property
    def proxy_addresses(self) -> List[str]:
        """Tokens after the direct address, in header order.

        These are addresses claimed by proxies. No validation is performed
        on this list itself; see :attr:`valid_tokens` to get only the ones
        that parse as real IPs.
        """
        return list(self._tokens[1:])

    @property
    def valid_tokens(self) -> List[str]:
        """Only tokens that parse as IPv4 or IPv6."""
        return [t for t, ok in zip(self._tokens, self._validities) if ok]

    @property
    def invalid_tokens(self) -> List[str]:
        """Only tokens that failed IPv4/IPv6 validation."""
        return [t for t, ok in zip(self._tokens, self._validities) if not ok]

    def first_untrusted(self, trusted: Sequence[str]) -> Optional[str]:
        """The first (nearest) token that is NOT in the trusted set.

        "Trusted" is exact-string membership. Comparison is plain string
        equality after the existing per-token trim — callers must pass the
        same string form as the header contains (i.e., a canonical IP
        string, not a CIDR).

        Returns None when the list is empty. When every token is trusted,
        returns the leftmost (earliest) trusted token so callers always get
        a definite answer.
        """
        if not self._tokens:
            return None
        trusted_set = set(trusted)
        for token in self._tokens:
            if token not in trusted_set:
                return token
        return self._tokens[0]
