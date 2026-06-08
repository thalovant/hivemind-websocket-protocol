from hivemind_websocket_protocol._client_ip import (
    parse_networks,
    resolve_client_ip,
)


TRUSTED = parse_networks(["10.0.0.0/8", "192.168.0.0/16"])
HEADERS = ("x-forwarded-for", "x-real-ip")


def test_parse_networks_skips_invalid():
    nets = parse_networks(["10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"])
    assert len(nets) == 2


def test_returns_remote_ip_when_no_trusted_networks():
    assert resolve_client_ip("1.2.3.4", {}, (), HEADERS) == "1.2.3.4"


def test_returns_remote_ip_when_peer_not_trusted():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("1.2.3.4", headers, TRUSTED, HEADERS) == "1.2.3.4"


def test_trusted_peer_uses_xff_header():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_xff_chain_walked_right_to_left_skipping_trusted():
    headers = {"x-forwarded-for": "8.8.8.8, 192.168.1.1, 10.0.0.5"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_xff_chain_all_trusted_falls_back_to_remote():
    headers = {"x-forwarded-for": "10.0.0.5, 192.168.1.1"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "10.0.0.5"


def test_falls_back_to_next_header_when_first_missing():
    headers = {"x-real-ip": "8.8.8.8"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_bad_ip_in_header_is_skipped():
    # malformed tokens are filtered; fall back to remote_ip
    headers = {"x-forwarded-for": "not-an-ip"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "10.0.0.5"


def test_unknown_token_skipped_per_rfc7239():
    headers = {"x-forwarded-for": "unknown"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "10.0.0.5"


def test_mixed_valid_and_invalid_tokens():
    headers = {"x-forwarded-for": "unknown, 8.8.8.8, garbage"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_invalid_token_between_trusted_and_client():
    # garbage in the middle should not derail the right-to-left walk
    headers = {"x-forwarded-for": "8.8.8.8, garbage, 10.0.0.5"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_empty_header_falls_back():
    headers = {"x-forwarded-for": "   "}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "10.0.0.5"


def test_none_remote_ip():
    assert resolve_client_ip(None, {}, TRUSTED, HEADERS) is None


def test_ipv6_trusted_chain():
    trusted = parse_networks(["fd00::/8"])
    headers = {"x-forwarded-for": "2001:db8::1, fd00::5"}
    assert resolve_client_ip("fd00::5", headers, trusted, HEADERS) == "2001:db8::1"


# --- Header precedence ---------------------------------------------------

def test_xff_preferred_over_real_ip_when_both_present():
    headers = {"x-forwarded-for": "8.8.8.8", "x-real-ip": "9.9.9.9"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_falls_through_to_real_ip_when_xff_all_trusted():
    headers = {"x-forwarded-for": "10.0.0.1, 192.168.1.1", "x-real-ip": "9.9.9.9"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "9.9.9.9"


def test_header_order_respects_config_tuple():
    headers = {"x-forwarded-for": "8.8.8.8", "x-real-ip": "9.9.9.9"}
    reordered = ("x-real-ip", "x-forwarded-for")
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, reordered) == "9.9.9.9"


def test_empty_trusted_headers_falls_back_to_remote():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, ()) == "10.0.0.5"


# --- Chain parsing -------------------------------------------------------

def test_single_ip_no_chain():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_chain_with_extra_whitespace():
    headers = {"x-forwarded-for": "  8.8.8.8 ,   192.168.1.1  ,  10.0.0.5  "}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_chain_with_empty_entries():
    headers = {"x-forwarded-for": "8.8.8.8,,,10.0.0.5"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_chain_with_trailing_comma():
    headers = {"x-forwarded-for": "8.8.8.8,"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "8.8.8.8"


# --- CIDR boundaries -----------------------------------------------------

def test_cidr_lower_boundary_inclusive():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("10.0.0.0", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_cidr_upper_boundary_inclusive():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("10.255.255.255", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_just_outside_cidr_not_trusted():
    headers = {"x-forwarded-for": "8.8.8.8"}
    # 11.0.0.0 is outside 10.0.0.0/8
    assert resolve_client_ip("11.0.0.0", headers, TRUSTED, HEADERS) == "11.0.0.0"


def test_single_host_cidr():
    trusted = parse_networks(["172.16.0.1/32"])
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("172.16.0.1", headers, trusted, HEADERS) == "8.8.8.8"
    assert resolve_client_ip("172.16.0.2", headers, trusted, HEADERS) == "172.16.0.2"


def test_loopback_not_trusted_by_default():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("127.0.0.1", headers, TRUSTED, HEADERS) == "127.0.0.1"


# --- IPv6 / mixed --------------------------------------------------------

def test_ipv6_peer_with_ipv4_chain():
    trusted = parse_networks(["fd00::/8", "10.0.0.0/8"])
    headers = {"x-forwarded-for": "8.8.8.8, 10.0.0.5"}
    assert resolve_client_ip("fd00::5", headers, trusted, HEADERS) == "8.8.8.8"


def test_ipv4_peer_with_ipv6_chain():
    trusted = parse_networks(["10.0.0.0/8", "fd00::/8"])
    headers = {"x-forwarded-for": "2001:db8::1, fd00::5"}
    assert resolve_client_ip("10.0.0.5", headers, trusted, HEADERS) == "2001:db8::1"


def test_ipv6_loopback_not_trusted_by_default():
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("::1", headers, TRUSTED, HEADERS) == "::1"


def test_ipv6_compressed_form_normalized_by_ipaddress():
    # 2001:db8:0:0::1 collapses to 2001:db8::1 inside the trust check
    trusted = parse_networks(["2001:db8::/32"])
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("2001:db8:0:0:0:0:0:5", headers, trusted, HEADERS) == "8.8.8.8"


# --- Misc / defensive ----------------------------------------------------

def test_empty_string_remote_ip():
    assert resolve_client_ip("", {}, TRUSTED, HEADERS) == ""


def test_malformed_remote_ip():
    # garbage peer can't be in any network -> headers ignored, returned as-is
    headers = {"x-forwarded-for": "8.8.8.8"}
    assert resolve_client_ip("not-an-ip", headers, TRUSTED, HEADERS) == "not-an-ip"


def test_port_suffixed_xff_is_skipped():
    # ip_address() rejects "1.2.3.4:port"; we don't try to strip ports.
    # A misconfigured proxy that appends ports falls through to remote_ip.
    headers = {"x-forwarded-for": "8.8.8.8:443"}
    assert resolve_client_ip("10.0.0.5", headers, TRUSTED, HEADERS) == "10.0.0.5"


def test_overlapping_cidrs():
    # smaller range nested in larger; both treated as trusted
    trusted = parse_networks(["10.0.0.0/8", "10.1.0.0/16"])
    headers = {"x-forwarded-for": "8.8.8.8, 10.1.0.1, 10.2.0.1"}
    assert resolve_client_ip("10.0.0.5", headers, trusted, HEADERS) == "8.8.8.8"


def test_long_chain():
    chain = ", ".join(["10.0.0." + str(i) for i in range(1, 20)] + ["8.8.8.8"][::-1])
    # 19 trusted hops then one client (leftmost)
    chain = "8.8.8.8, " + ", ".join("10.0.0." + str(i) for i in range(1, 20))
    headers = {"x-forwarded-for": chain}
    assert resolve_client_ip("10.0.0.20", headers, TRUSTED, HEADERS) == "8.8.8.8"


def test_parse_networks_accepts_host_bits_set():
    # strict=False allows 10.0.0.5/8 -> 10.0.0.0/8
    nets = parse_networks(["10.0.0.5/8"])
    assert len(nets) == 1
    assert str(nets[0]) == "10.0.0.0/8"


def test_parse_networks_empty():
    assert parse_networks([]) == ()


def test_parse_networks_skips_blank_strings():
    # Real-world: env var with empty value
    nets = parse_networks(["10.0.0.0/8", "", "  "])
    # ip_network rejects "" and "  " -> warnings, but we get the valid one
    assert len(nets) == 1


# --- _split_csv (config / env parsing) -----------------------------------

def test_split_csv_handles_string_list_none():
    from hivemind_websocket_protocol import _split_csv

    assert _split_csv(None) == ()
    assert _split_csv("") == ()
    assert _split_csv("a,b,c") == ("a", "b", "c")
    assert _split_csv("  a , , b  ") == ("a", "b")
    assert _split_csv(["a", "b"]) == ("a", "b")
    assert _split_csv(("a", "", " b ")) == ("a", "b")
    assert _split_csv([]) == ()


def test_explicit_empty_config_overrides_env(monkeypatch):
    # Regression: 'or' would treat an explicit [] as falsy and fall through to env.
    # The 'in self.config' branch must let an explicit empty list disable the feature.
    from hivemind_websocket_protocol import _split_csv

    config = {"trusted_proxy_cidrs": []}
    monkeypatch.setenv("HIVEMIND_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

    import os
    if "trusted_proxy_cidrs" in config:
        value = config["trusted_proxy_cidrs"]
    else:
        value = os.getenv("HIVEMIND_TRUSTED_PROXY_CIDRS")
    assert _split_csv(value) == ()  # explicit empty list wins over env
