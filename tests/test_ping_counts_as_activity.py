from unittest import mock

import pytest

tornado_websocket = pytest.importorskip("tornado.websocket")
from hivemind_websocket_protocol import HiveMindTornadoWebSocket  # noqa: E402


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setattr(tornado_websocket.WebSocketHandler, "on_ping", lambda self, data: None)
    loop = mock.Mock()
    executor = object()
    monkeypatch.setattr(HiveMindTornadoWebSocket, "loop", loop, raising=False)
    monkeypatch.setattr(HiveMindTornadoWebSocket, "inbound_executor", executor, raising=False)
    instance = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    instance.loop = loop
    return instance


def test_a_ping_from_an_admitted_client_records_activity_off_the_loop(handler):
    client = object()
    protocol = mock.Mock()
    handler.client = client
    handler.hm_protocol = protocol

    handler.on_ping(b"")

    handler.loop.run_in_executor.assert_called_once()
    _, func, arg = handler.loop.run_in_executor.call_args.args
    assert func == protocol.update_last_seen
    assert arg is client


def test_a_ping_before_admission_is_not_activity(handler):
    protocol = mock.Mock()
    handler.client = object()
    handler.hm_protocol = protocol
    handler._client_admitted = False

    handler.on_ping(b"")

    handler.loop.run_in_executor.assert_not_called()
