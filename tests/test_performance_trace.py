import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from hivemind_websocket_protocol import _performance_trace


def test_message_request_id_finds_nested_transport_payload():
    message = SimpleNamespace(
        payload={"context": {"qa_query_id": "request-nested"}}
    )

    assert _performance_trace.message_request_id(message) == "request-nested"


def test_trace_emits_bounded_diagnostic_event(monkeypatch):
    monkeypatch.setenv("HIVEMIND_PERFORMANCE_TRACE", "true")
    info = MagicMock()
    monkeypatch.setattr(_performance_trace._LOG, "info", info)

    _performance_trace.trace_performance_stage(
        "listener_receive",
        request_id="r" * 300,
        at_unix_ns=123_456_789,
        at_monotonic_ns=987_654_321,
    )

    info.assert_called_once()
    event = json.loads(info.call_args.args[1])
    assert event == {
        "at_monotonic_ns": 987_654_321,
        "at_unix_ns": 123_456_789,
        "request_id": "r" * 256,
        "stage": "listener_receive",
    }


def test_disabled_trace_does_not_inspect_message(monkeypatch):
    monkeypatch.delenv("HIVEMIND_PERFORMANCE_TRACE", raising=False)
    inspect_request_id = MagicMock()
    monkeypatch.setattr(
        _performance_trace,
        "message_request_id",
        inspect_request_id,
    )

    _performance_trace.trace_performance_stage(
        "listener_receive",
        message=object(),
    )

    inspect_request_id.assert_not_called()
