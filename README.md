# x_forwarded_for_chain

Parse the `X-Forwarded-For` header chain, identify the direct and proxy-originated addresses, and apply trusted-proxy filtering. Standard library only.

## Usage

```python
from x_forwarded_for_chain import XForwardedForChain, parse_x_forwarded_for

chain = XForwardedForChain("203.0.113.5, 198.51.100.1, 192.0.2.9")
chain.direct_address           # "203.0.113.5"  (the nearest hop)
chain.proxy_addresses          # ["198.51.100.1", "192.0.2.9"]
chain.valid_tokens             # only tokens that parse as IPv4/IPv6
chain.first_untrusted(["198.51.100.1", "192.0.2.9"])  # "203.0.113.5"

parse_x_forwarded_for(None)    # []
parse_x_forwarded_for("a, b")  # ["a", "b"]
```

## Why

When your service sits behind one or more HTTP proxies, `X-Forwarded-For` is the only hint at the originating client's address. The header is a right-to-left chain: each proxy appends the address it received the connection from, so the leftmost token is the nearest hop and the rightmost is (claimed to be) the originating client. The awkward part is provenance — every entry is self-reported by a proxy, so only addresses that arrived through a proxy you trust can be believed.

This library takes one clear position on each ambiguous question:

- The **direct address** is the first (leftmost) token. It is the peer that opened the TCP connection to the nearest proxy in the chain.
- `first_untrusted` walks leftward from the nearest hop and returns the first token that is **not** in your trusted set. If every hop is trusted, it returns the leftmost trusted token — you always get a definite answer.
- Trusted means **exact string equality** against the canonical IP string. No CIDR, no prefix matching. If you need CIDR, do that outside and pass exact strings in. The trade-off is that the library will not silently accept `203.0.113.5/32` as equivalent to `203.0.113.5`.

## Edge cases

- Empty header, `None`, or a non-string value yield an empty token list and `None` for the direct address.
- Tokens are trimmed of surrounding ASCII whitespace; empty tokens are dropped; duplicates are preserved (the chain can legitimately repeat an address).
- `X-Forwarded-For` is sometimes sent as multiple header lines. This library does not collapse them — you must join the values yourself before constructing `XForwardedForChain`, because the ordering semantics of multiple headers is deployment-specific and I will not guess it.
