from unittest import mock

import pytest

tornado_websocket = pytest.importorskip("tornado.websocket")
from hivemind_websocket_protocol import HiveMindTornadoWebSocket  # noqa: E402


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setattr(tornado_websocket.WebSocketHandler, "on_ping", lambda self, data: None)
    return HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)


def test_a_ping_from_an_admitted_client_counts_as_activity(handler):
    client = object()
    protocol = mock.Mock()
    handler.client = client
    handler.hm_protocol = protocol

    handler.on_ping(b"")

    protocol.touch_last_seen.assert_called_once_with(client)


def test_a_ping_before_admission_is_not_activity(handler):
    protocol = mock.Mock()
    handler.client = object()
    handler.hm_protocol = protocol
    handler._client_admitted = False

    handler.on_ping(b"")

    protocol.touch_last_seen.assert_not_called()
