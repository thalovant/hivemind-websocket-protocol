"""A stored password below the strength floor must reject, not crash.

check_password_strength raises WeakPasswordError -- a ValueError -- when the
client's stored credential is below the configured floor. Left uncaught it
escaped open() as an internal error and the socket was torn down with no
reason, indistinguishable from a crash to the client.
"""
from types import SimpleNamespace

import pytest
from poorman_handshake.symmetric.strength import WeakPasswordError

import hivemind_websocket_protocol as websocket_protocol
from tests.test_protocol_unit import _auth_user, _open_handler, _run_open


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setattr(
        websocket_protocol, "_new_client_handshake", lambda path: SimpleNamespace()
    )
    return _open_handler


def test_weak_stored_password_rejects_with_a_reason(handler, monkeypatch):
    def refuse(password, min_bits=None):
        raise WeakPasswordError("password is too guessable")

    monkeypatch.setattr(websocket_protocol, "_new_password_handshake", refuse)

    user = _auth_user()
    user.password = "hunter2"
    seen, invalid, closes = [], [], []
    h = handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=seen,
        invalid_clients=invalid,
        closes=closes,
    )
    h.prefer_preshared_key = False
    h.password_min_bits = 80.0
    h.handshake_executor = None

    _run_open(h)  # must not raise

    assert closes, "the socket must be closed explicitly"
    assert closes[-1]["kwargs"].get("code") == 1008
    assert "strength" in closes[-1]["kwargs"].get("reason", "")
    assert not seen, "a rejected client must never be admitted"
    assert not invalid, (
        "a weak STORED password is the operator's record failing policy, not the "
        "client presenting bad credentials; it must not fire on_invalid_key"
    )


def test_a_strong_password_is_not_affected(handler, monkeypatch):
    monkeypatch.setattr(
        websocket_protocol,
        "_new_password_handshake",
        lambda password, min_bits=None: SimpleNamespace(),
    )
    user = _auth_user()
    user.password = "correct-horse-battery-staple-9931"
    seen, closes = [], []
    h = handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=seen,
        closes=closes,
    )
    h.prefer_preshared_key = False
    h.password_min_bits = 80.0
    h.handshake_executor = None

    _run_open(h)

    assert not [c for c in closes if c["kwargs"].get("code") == 1008]
