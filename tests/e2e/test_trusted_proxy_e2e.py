"""End-to-end: trusted-proxy IP resolution over real WebSocket.

Uses the `tornado_server_with_proxy` fixture which configures
`127.0.0.0/8` as a trusted proxy CIDR. The test client (also on
127.0.0.1) is in that range, so X-Forwarded-For headers it sends are
honoured. A plain `tornado_server` (no trusted CIDRs) is used as the
negative control.
"""
import socket
import time

import websocket as ws_client
import pybase64

from hivemind_websocket_protocol import HiveMindTornadoWebSocket


# --- helpers --------------------------------------------------------------

def _capture_source_ip():
    """Monkey-patch the handler's _client_ip to record what it resolves.

    Returns `(values_list, restore_fn)`. Tests call restore_fn() in a
    finally block.
    """
    captured = []
    original = HiveMindTornadoWebSocket._client_ip

    def _spy(self):
        value = original(self)
        captured.append(value)
        return value

    HiveMindTornadoWebSocket._client_ip = _spy
    return captured, lambda: setattr(HiveMindTornadoWebSocket, "_client_ip", original)


def _auth_url(server, useragent="e2e"):
    raw = f"{useragent}:{server.api_key}"
    b64 = pybase64.b64encode(raw.encode()).decode()
    return f"{server.url}/?authorization={b64}"


def _connect(url, *, headers=None, timeout=3):
    sock = ws_client.create_connection(url, header=headers or [], timeout=timeout)
    sock.settimeout(1)
    # Drain HELLO so the server-side handler has fully entered open().
    # The recv may legitimately time out if the server hasn't pushed yet;
    # any other error is a real failure.
    try:
        sock.recv()
    except (ws_client.WebSocketTimeoutException, socket.timeout):
        pass
    return sock


# --- behaviour tests ------------------------------------------------------

def test_x_forwarded_for_resolves_to_client(tornado_server_with_proxy):
    """When the peer is in a trusted CIDR, XFF is consulted."""
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server_with_proxy),
            headers=["X-Forwarded-For: 8.8.8.8"],
        )
        sock.close()
        time.sleep(0.1)
        assert "8.8.8.8" in captured, \
            f"expected 8.8.8.8 from X-Forwarded-For, got {captured!r}"
    finally:
        restore()


def test_xff_chain_walks_right_to_left(tornado_server_with_proxy):
    """A chain with the real client leftmost; intermediate is trusted."""
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server_with_proxy),
            headers=["X-Forwarded-For: 8.8.8.8, 127.0.0.5"],
        )
        sock.close()
        time.sleep(0.1)
        # Right-to-left: 127.0.0.5 is trusted -> skip; 8.8.8.8 wins.
        assert "8.8.8.8" in captured
    finally:
        restore()


def test_x_real_ip_used_when_xff_missing(tornado_server_with_proxy):
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server_with_proxy),
            headers=["X-Real-IP: 4.4.4.4"],
        )
        sock.close()
        time.sleep(0.1)
        assert "4.4.4.4" in captured
    finally:
        restore()


def test_xff_preferred_over_x_real_ip(tornado_server_with_proxy):
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server_with_proxy),
            headers=["X-Forwarded-For: 8.8.8.8", "X-Real-IP: 4.4.4.4"],
        )
        sock.close()
        time.sleep(0.1)
        assert "8.8.8.8" in captured
    finally:
        restore()


def test_no_forwarded_header_falls_back_to_remote_ip(tornado_server_with_proxy):
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(_auth_url(tornado_server_with_proxy))
        sock.close()
        time.sleep(0.1)
        assert any(ip == "127.0.0.1" for ip in captured), \
            f"expected 127.0.0.1 fallback, got {captured!r}"
    finally:
        restore()


def test_malformed_xff_falls_back_to_remote_ip(tornado_server_with_proxy):
    """RFC 7239 'unknown' or garbage tokens are skipped."""
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server_with_proxy),
            headers=["X-Forwarded-For: unknown"],
        )
        sock.close()
        time.sleep(0.1)
        # Falls back to the actual remote peer
        assert any(ip == "127.0.0.1" for ip in captured)
    finally:
        restore()


# --- negative control: feature off ---------------------------------------

def test_xff_ignored_when_no_trusted_cidrs(tornado_server):
    """Without trusted CIDRs, XFF must be ignored entirely."""
    captured, restore = _capture_source_ip()
    try:
        sock = _connect(
            _auth_url(tornado_server),
            headers=["X-Forwarded-For: 8.8.8.8"],
        )
        sock.close()
        time.sleep(0.1)
        assert "8.8.8.8" not in captured, \
            "XFF must not be trusted when no proxy CIDRs configured"
        assert any(ip == "127.0.0.1" for ip in captured)
    finally:
        restore()
