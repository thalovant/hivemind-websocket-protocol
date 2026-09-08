"""A 5.x Client record has no crypto_key attribute at all.

HiveMind-core 5.x derives the v3 Noise pre-shared key from the password and
removed the field from the Client model. Reading it directly raised
AttributeError inside admission, which is what turned the whole e2e suite red
once CI picked up a 5.x hivemind-plugin-manager.
"""
from types import SimpleNamespace

import pytest

import hivemind_websocket_protocol as websocket_protocol
from tests.test_protocol_unit import _open_handler, _run_open


def _v5_user():
    # deliberately no crypto_key attribute
    return SimpleNamespace(
        client_id=1, name="v5-client", skill_blacklist=[], intent_blacklist=[],
        allowed_types=["recognizer_loop:utterance"], can_broadcast=True,
        can_propagate=True, can_escalate=True, is_admin=False, password=None,
    )


def test_a_client_record_without_crypto_key_is_admitted(monkeypatch):
    monkeypatch.setattr(websocket_protocol, "_new_client_handshake", lambda path: SimpleNamespace())
    seen, closes = [], []
    handler = _open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: _v5_user()),
        seen_clients=seen, closes=closes,
    )
    _run_open(handler)  # must not raise AttributeError
    assert seen, "the client should have been admitted"
    assert handler.client.crypto_key is None
