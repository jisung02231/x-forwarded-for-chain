import unittest

from x_forwarded_for_chain import XForwardedForChain, parse_x_forwarded_for


class TestParseXForwardedFor(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(parse_x_forwarded_for(None), [])

    def test_empty_string_returns_empty(self):
        self.assertEqual(parse_x_forwarded_for(""), [])

    def test_single_token(self):
        self.assertEqual(parse_x_forwarded_for("203.0.113.5"), ["203.0.113.5"])

    def test_multiple_tokens_preserve_order(self):
        header = "203.0.113.5, 198.51.100.1, 192.0.2.9"
        self.assertEqual(
            parse_x_forwarded_for(header),
            ["203.0.113.5", "198.51.100.1", "192.0.2.9"],
        )

    def test_whitespace_around_tokens_is_trimmed(self):
        header = "  203.0.113.5 ,\t198.51.100.1  , 192.0.2.9 "
        self.assertEqual(
            parse_x_forwarded_for(header),
            ["203.0.113.5", "198.51.100.1", "192.0.2.9"],
        )

    def test_empty_tokens_are_dropped(self):
        self.assertEqual(parse_x_forwarded_for(",,,"), [])
        self.assertEqual(parse_x_forwarded_for(", 203.0.113.5 ,"), ["203.0.113.5"])

    def test_non_string_returns_empty(self):
        self.assertEqual(parse_x_forwarded_for(12345), [])
        self.assertEqual(parse_x_forwarded_for(["203.0.113.5"]), [])

    def test_does_not_deduplicate(self):
        self.assertEqual(
            parse_x_forwarded_for("203.0.113.5, 203.0.113.5"),
            ["203.0.113.5", "203.0.113.5"],
        )


class TestXForwardedForChain(unittest.TestCase):
    def test_tokens_returns_raw_parsed_list(self):
        chain = XForwardedForChain("203.0.113.5, 198.51.100.1")
        self.assertEqual(chain.tokens, ["203.0.113.5", "198.51.100.1"])

    def test_direct_address_is_first_token(self):
        chain = XForwardedForChain("203.0.113.5, 198.51.100.1, 192.0.2.9")
        self.assertEqual(chain.direct_address, "203.0.113.5")

    def test_direct_address_none_when_empty(self):
        self.assertIsNone(XForwardedForChain("").direct_address)
        self.assertIsNone(XForwardedForChain(None).direct_address)

    def test_proxy_addresses_skips_first(self):
        chain = XForwardedForChain("203.0.113.5, 198.51.100.1, 192.0.2.9")
        self.assertEqual(chain.proxy_addresses, ["198.51.100.1", "192.0.2.9"])

    def test_proxy_addresses_empty_for_single_token(self):
        self.assertEqual(XForwardedForChain("203.0.113.5").proxy_addresses, [])

    def test_valid_tokens_filters_invalid(self):
        chain = XForwardedForChain("203.0.113.5, not-an-ip, 192.0.2.9")
        self.assertEqual(chain.valid_tokens, ["203.0.113.5", "192.0.2.9"])

    def test_invalid_tokens_collected(self):
        chain = XForwardedForChain("203.0.113.5, not-an-ip, 192.0.2.9")
        self.assertEqual(chain.invalid_tokens, ["not-an-ip"])

    def test_ipv6_accepted(self):
        chain = XForwardedForChain("2001:db8::1, 2001:db8::2")
        self.assertEqual(chain.direct_address, "2001:db8::1")
        self.assertEqual(chain.valid_tokens, ["2001:db8::1", "2001:db8::2"])
        self.assertEqual(chain.invalid_tokens, [])

    def test_first_untrusted_returns_first_non_member(self):
        chain = XForwardedForChain("203.0.113.5, 198.51.100.1, 192.0.2.9")
        # Direct address is not trusted -> returned immediately.
        self.assertEqual(chain.first_untrusted(["198.51.100.1", "192.0.2.9"]), "203.0.113.5")

    def test_first_untrusted_skips_trusted_direct(self):
        chain = XForwardedForChain("198.51.100.1, 203.0.113.5, 192.0.2.9")
        self.assertEqual(chain.first_untrusted(["198.51.100.1", "192.0.2.9"]), "203.0.113.5")

    def test_first_untrusted_all_trusted_returns_leftmost(self):
        chain = XForwardedForChain("198.51.100.1, 203.0.113.5")
        self.assertEqual(chain.first_untrusted(["198.51.100.1", "203.0.113.5"]), "198.51.100.1")

    def test_first_untrusted_empty_list(self):
        self.assertIsNone(XForwardedForChain("").first_untrusted(["198.51.100.1"]))

    def test_first_untrusted_empty_trusted_set(self):
        chain = XForwardedForChain("203.0.113.5, 198.51.100.1")
        self.assertEqual(chain.first_untrusted([]), "203.0.113.5")

    def test_first_untrusted_is_exact_string_match(self):
        # Canonical form matters; a CIDR-shaped entry does not match a bare IP.
        chain = XForwardedForChain("203.0.113.5")
        self.assertEqual(chain.first_untrusted(["203.0.113.5/32"]), "203.0.113.5")


if __name__ == "__main__":
    unittest.main()
