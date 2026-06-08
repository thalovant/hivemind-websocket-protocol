"""Smoke test verifying hivescope wiring against hivemind-websocket-protocol."""
from hivescope.assertions import assert_handshake_complete


def test_hivescope_wiring_handshake(hive):
    """A single-satellite topology completes a handshake end-to-end."""
    master, satellite = hive
    assert_handshake_complete(master, satellite)
