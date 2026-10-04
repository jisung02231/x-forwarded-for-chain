"""Public API for x_forwarded_for_chain."""

from .core import XForwardedForChain, parse_x_forwarded_for

__all__ = ["XForwardedForChain", "parse_x_forwarded_for"]
