"""Unit-level coverage for the bits e2e tests don't reach directly.

Targets:
- `HiveMindWebsocketProtocol.run()` for the plain (ssl=False) path,
  including the actual `application.listen()` call.
- `create_self_signed_cert()` certificate / key generation.
- version.py module loading.
"""
import asyncio
import logging
import os
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pybase64
import pytest
from hivemind_plugin_manager.database import AbstractRemoteDB
from hivescope.node import MasterNode
from tornado.websocket import WebSocketClosedError

import hivemind_websocket_protocol as websocket_protocol
from hivemind_websocket_protocol import (
    _HANDSHAKE_TEMPLATE_CACHE,
    _PASSWORD_STRENGTH_CACHE,
    DEFAULT_AUTH_EXECUTOR_WORKERS,
    DEFAULT_CONNECT_LIFECYCLE_EXECUTOR_WORKERS,
    DEFAULT_DISCONNECT_EXECUTOR_WORKERS,
    DEFAULT_HANDSHAKE_EXECUTOR_WORKERS,
    DEFAULT_INBOUND_CLIENT_QUEUE_SIZE,
    DEFAULT_INBOUND_EXECUTOR_WORKERS,
    DEFAULT_INBOUND_QUEUE_SIZE,
    DEFAULT_SLOW_ADMISSION_LOG_MS,
    DEFAULT_WEBSOCKET_PING_INTERVAL,
    DEFAULT_WEBSOCKET_PING_TIMEOUT,
    HiveMindTornadoWebSocket,
    HiveMindWebsocketProtocol,
    _finish_disconnect_callback,
    _finish_websocket_write,
    _new_client_handshake,
    _new_password_handshake,
    _refresh_local_client_database,
    _write_websocket_message,
)


@pytest.fixture(autouse=True)
def _reset_websocket_sync_state():
    HiveMindTornadoWebSocket._last_sync_ts = 0.0
    HiveMindTornadoWebSocket._last_sync_error = None
    HiveMindTornadoWebSocket.auth_admission_capacity = None
    HiveMindTornadoWebSocket.auth_pending = 0
    HiveMindTornadoWebSocket.inbound_executor = None
    HiveMindTornadoWebSocket.inbound_slots = None
    HiveMindTornadoWebSocket.inbound_admission_capacity = None
    HiveMindTornadoWebSocket.inbound_client_queue_size = None
    HiveMindTornadoWebSocket.inbound_pending = 0
    _PASSWORD_STRENGTH_CACHE.clear()
    yield
    _PASSWORD_STRENGTH_CACHE.clear()
    HiveMindTornadoWebSocket.auth_admission_capacity = None
    HiveMindTornadoWebSocket.auth_pending = 0
    HiveMindTornadoWebSocket.inbound_executor = None
    HiveMindTornadoWebSocket.inbound_slots = None
    HiveMindTornadoWebSocket.inbound_admission_capacity = None
    HiveMindTornadoWebSocket.inbound_client_queue_size = None
    HiveMindTornadoWebSocket.inbound_pending = 0


# --- version.py module load ------------------------------------------------

def test_version_module_exposes_constants_and_string():
    from hivemind_websocket_protocol import version as v
    assert isinstance(v.VERSION_MAJOR, int)
    assert isinstance(v.VERSION_MINOR, int)
    assert isinstance(v.VERSION_BUILD, int)
    assert isinstance(v.VERSION_ALPHA, int)
    assert isinstance(v.__version__, str)
    assert v.__version__.startswith(
        f"{v.VERSION_MAJOR}.{v.VERSION_MINOR}.{v.VERSION_BUILD}"
    )


# --- database refresh ------------------------------------------------------

def test_authorization_refreshes_file_backed_database():
    database = SimpleNamespace(db=object(), sync=Mock())

    assert _refresh_local_client_database(database) is True

    database.sync.assert_called_once_with()


def test_authorization_never_repairs_remote_database():
    database = SimpleNamespace(
        db=Mock(spec=AbstractRemoteDB),
        sync=Mock(side_effect=AssertionError("remote sync entered WSS auth path")),
    )

    for _ in range(400):
        assert _refresh_local_client_database(database) is False

    database.sync.assert_not_called()


def test_closed_websocket_write_future_is_consumed():
    future = Future()
    future.set_exception(WebSocketClosedError())

    _finish_websocket_write(future)

    assert future.exception() is not None


def test_synchronous_closed_websocket_write_is_routine():
    handler = SimpleNamespace(
        write_message=Mock(side_effect=WebSocketClosedError()),
    )

    _write_websocket_message(handler, "payload", False)

    handler.write_message.assert_called_once_with("payload", False)


def test_synchronous_websocket_write_failure_completes_send_contract(
        monkeypatch):
    """A direct write error must not leave the returned Future unresolved."""
    handler = SimpleNamespace(
        write_message=Mock(side_effect=RuntimeError("serialization failed")),
    )
    logged = []
    monkeypatch.setattr(websocket_protocol.LOG, "error", logged.append)

    completion = _write_websocket_message(handler, "payload", False)

    with pytest.raises(RuntimeError, match="serialization failed"):
        completion.result(timeout=0.1)
    assert len(logged) == 1
    assert "RuntimeError" in logged[0]


def test_canceled_websocket_write_is_not_queued(open_handler):
    """Do not deliver a frame canceled after the public send scheduled it."""
    scheduled = []
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: _auth_user()),
        seen_clients=[],
    )
    handler.loop = SimpleNamespace(
        add_callback=lambda callback, *args, **kwargs: scheduled.append(
            (callback, args, kwargs)
        )
    )
    handler.write_message = Mock()
    handler.event_loop_thread_id = None

    _run_open(handler)
    completion = handler.client.send_msg("payload", False)
    assert len(scheduled) == 1
    assert completion.cancel()

    callback, args, kwargs = scheduled.pop()
    returned = callback(*args, **kwargs)

    assert returned is completion
    handler.write_message.assert_not_called()


def test_websocket_write_completion_tracks_tornado_future():
    tornado_future = Future()
    handler = SimpleNamespace(write_message=Mock(return_value=tornado_future))

    completion = _write_websocket_message(handler, "payload", False)
    assert not completion.done()

    tornado_future.set_result(None)
    assert completion.result(timeout=0.1) is None


def test_authorization_admission_is_strictly_bounded():
    HiveMindTornadoWebSocket.auth_admission_capacity = 2
    handlers = [
        HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
        for _ in range(3)
    ]
    for handler in handlers:
        handler._auth_admission_reserved = False

    assert handlers[0]._reserve_auth_admission() is True
    assert handlers[1]._reserve_auth_admission() is True
    assert handlers[2]._reserve_auth_admission() is False
    assert HiveMindTornadoWebSocket.auth_pending == 2

    handlers[0]._release_auth_admission()
    assert handlers[2]._reserve_auth_admission() is True
    assert HiveMindTornadoWebSocket.auth_pending == 2

    handlers[1]._release_auth_admission()
    handlers[2]._release_auth_admission()
    HiveMindTornadoWebSocket.auth_admission_capacity = None


def test_inbound_admission_is_bounded_globally_and_per_client():
    HiveMindTornadoWebSocket.inbound_admission_capacity = 3
    HiveMindTornadoWebSocket.inbound_client_queue_size = 2
    first = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    second = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)

    assert first._reserve_inbound_admission() is True
    assert first._reserve_inbound_admission() is True
    assert first._reserve_inbound_admission() is False
    assert second._reserve_inbound_admission() is True
    assert second._reserve_inbound_admission() is False
    assert HiveMindTornadoWebSocket.inbound_pending == 3

    first._release_inbound_admission()
    assert second._reserve_inbound_admission() is True
    assert HiveMindTornadoWebSocket.inbound_pending == 3

    first._release_inbound_admission()
    second._release_inbound_admission()
    second._release_inbound_admission()
    assert HiveMindTornadoWebSocket.inbound_pending == 0


def test_inbound_overload_closes_only_the_owning_socket():
    HiveMindTornadoWebSocket.inbound_admission_capacity = 1
    HiveMindTornadoWebSocket.inbound_client_queue_size = 1
    blocker = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.close = Mock()

    assert blocker._reserve_inbound_admission() is True
    asyncio.run(handler.on_message("payload"))

    handler.close.assert_called_once_with(
        code=1013,
        reason="inbound processing overloaded",
    )
    assert blocker._inbound_closed is False
    blocker._release_inbound_admission()


def test_disconnect_callback_failures_are_observed(monkeypatch):
    logged = []
    future = Future()
    future.set_exception(RuntimeError("disconnect failed"))
    monkeypatch.setattr(websocket_protocol.LOG, "error", logged.append)

    _finish_disconnect_callback(future)

    assert len(logged) == 1
    assert "RuntimeError" in logged[0]


def test_messages_from_different_clients_run_concurrently_off_event_loop():
    handled = []

    def slow_handshake(message, client):
        time.sleep(0.05)
        handled.append(client.peer)

    handlers = []
    for index in range(8):
        handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
        message = SimpleNamespace(
            msg_type=websocket_protocol.HiveMessageType.HANDSHAKE,
            payload={},
        )
        handler.client = SimpleNamespace(
            peer=f"client-{index}",
            decode=lambda payload, decoded=message: decoded,
        )
        handler.hm_protocol = SimpleNamespace(handle_message=slow_handshake)
        handler.loop = SimpleNamespace(
            run_in_executor=lambda executor, callback, *args: (
                asyncio.get_running_loop().run_in_executor(
                    executor,
                    callback,
                    *args,
                )
            ),
        )
        handlers.append(handler)

    executor = ThreadPoolExecutor(max_workers=8)

    async def run_all():
        slots = asyncio.Semaphore(8)
        for handler in handlers:
            handler.inbound_executor = executor
            handler.inbound_slots = slots
        started = time.monotonic()
        await asyncio.gather(*(
            handler.on_message("payload") for handler in handlers
        ))
        return time.monotonic() - started

    try:
        elapsed = asyncio.run(run_all())
    finally:
        executor.shutdown(wait=True)

    assert elapsed < 0.25
    assert len(handled) == 8


def test_messages_from_one_client_preserve_receive_order():
    handled = []
    executor = ThreadPoolExecutor(max_workers=4)
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.source_ip = None
    handler.client = SimpleNamespace(
        peer="ordered-client",
        decode=lambda payload: SimpleNamespace(
            msg_type=websocket_protocol.HiveMessageType.HANDSHAKE,
            payload=payload,
        ),
    )
    handler.hm_protocol = SimpleNamespace(
        handle_message=lambda message, _client: handled.append(message.payload),
    )
    handler.loop = SimpleNamespace(
        run_in_executor=lambda selected, callback, *args: (
            asyncio.get_running_loop().run_in_executor(
                selected,
                callback,
                *args,
            )
        ),
    )
    handler.inbound_executor = executor

    async def run_all():
        handler.inbound_slots = asyncio.Semaphore(4)
        await asyncio.gather(*(
            handler.on_message(payload) for payload in ("one", "two", "three")
        ))

    try:
        asyncio.run(run_all())
    finally:
        executor.shutdown(wait=True)

    assert handled == ["one", "two", "three"]


def test_close_cancels_queued_inbound_work():
    handled = Mock()
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.source_ip = None
    handler.client = SimpleNamespace(
        peer="closing-client",
        decode=Mock(),
    )
    handler.hm_protocol = SimpleNamespace(handle_message=handled)
    handler.request = SimpleNamespace(remote_ip="127.0.0.1")
    handler._auth_lookup_future = None
    handler._auth_task = None
    handler._auth_admission_reserved = False
    handler._client_admitted = False

    async def close_while_queued():
        handler._ensure_inbound_state()
        await handler._inbound_lock.acquire()
        task = asyncio.create_task(handler.on_message("queued"))
        await asyncio.sleep(0)
        assert handler._inbound_pending == 1
        handler.on_close()
        handler._inbound_lock.release()
        await task

    asyncio.run(close_while_queued())

    assert handler._inbound_closed is True
    assert handler._inbound_pending == 0
    assert HiveMindTornadoWebSocket.inbound_pending == 0
    handler.client.decode.assert_not_called()
    handled.assert_not_called()


def test_on_message_releases_the_semaphore_it_acquired():
    original_slots = None
    replacement_slots = None
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.source_ip = None
    handler.client = SimpleNamespace(
        peer="client",
        decode=lambda payload: SimpleNamespace(
            msg_type=websocket_protocol.HiveMessageType.HANDSHAKE,
            payload=payload,
        ),
    )
    handler.hm_protocol = SimpleNamespace(handle_message=lambda *_: None)

    async def replace_executor_state(_executor, callback, *args):
        handler.inbound_slots = replacement_slots
        handler.inbound_executor = None
        callback(*args)

    handler.loop = SimpleNamespace(run_in_executor=replace_executor_state)

    async def run_message():
        nonlocal original_slots, replacement_slots
        original_slots = asyncio.BoundedSemaphore(1)
        replacement_slots = asyncio.BoundedSemaphore(1)
        handler.inbound_slots = original_slots
        handler.inbound_executor = object()
        await handler.on_message("payload")

    asyncio.run(run_message())

    assert original_slots is not None
    assert replacement_slots is not None
    assert original_slots._value == 1
    assert replacement_slots._value == 1


def test_on_message_logs_type_without_formatting_payload(monkeypatch):
    sentinel = "private user utterance"
    message = SimpleNamespace(
        msg_type=websocket_protocol.HiveMessageType.BUS,
        payload=SimpleNamespace(
            msg_type="intent",
            context={"utterance": sentinel},
        ),
    )
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.source_ip = None
    handler.client = SimpleNamespace(
        peer="client-1",
        decode=lambda _payload: message,
    )
    handler.hm_protocol = SimpleNamespace(handle_message=Mock())
    debug = Mock()
    monkeypatch.setattr(websocket_protocol._log, "debug", debug)

    asyncio.run(handler.on_message("wire payload"))

    debug.assert_called_once_with(
        "Received %s message: %s",
        "client-1",
        websocket_protocol.HiveMessageType.BUS,
    )
    assert sentinel not in repr(debug.call_args)
    handler.hm_protocol.handle_message.assert_called_once_with(
        message, handler.client)


def test_hotpath_logger_delegates_configuration_to_host_runtime():
    logger = websocket_protocol._log

    assert logger is logging.getLogger(websocket_protocol.__name__)
    assert logger.level == 0
    assert logger.handlers == []
    assert logger.propagate is True


def test_request_summary_redacts_authorization_query():
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.request = SimpleNamespace(
        method="GET",
        path="/",
        uri="/?authorization=encoded-disposable-secret",
        remote_ip="203.0.113.10",
    )

    summary = handler._request_summary()

    assert summary == "GET / (203.0.113.10)"
    assert "authorization" not in summary
    assert "encoded-disposable-secret" not in summary


# --- listener handshake key cache -----------------------------------------

class _FakeHandshake:
    created = 0

    def __init__(self, path):
        type(self).created += 1
        self.private_key = object()
        self.path = path
        self.target_key = None
        self.secret = None


@pytest.fixture
def fake_handshake(monkeypatch):
    _FakeHandshake.created = 0
    _HANDSHAKE_TEMPLATE_CACHE.clear()
    monkeypatch.setattr(websocket_protocol, "HandShake", _FakeHandshake)
    yield _FakeHandshake
    _HANDSHAKE_TEMPLATE_CACHE.clear()


def test_client_handshake_reuses_key_parse_with_isolated_state(tmp_path, fake_handshake):
    key_path = tmp_path / "listener.pem"
    key_path.write_text("listener-key-v1")

    with ThreadPoolExecutor(max_workers=16) as executor:
        handshakes = list(executor.map(lambda _: _new_client_handshake(str(key_path)), range(400)))

    assert fake_handshake.created == 1
    assert len({id(handshake) for handshake in handshakes}) == 400
    assert len({id(handshake.private_key) for handshake in handshakes}) == 1

    handshakes[0].target_key = object()
    handshakes[0].secret = b"connection-local"
    assert all(handshake.target_key is None for handshake in handshakes[1:])
    assert all(handshake.secret is None for handshake in handshakes[1:])


def test_client_handshake_reloads_rotated_key(tmp_path, fake_handshake):
    key_path = tmp_path / "listener.pem"
    key_path.write_text("listener-key-v1")
    first = _new_client_handshake(str(key_path))

    key_path.write_text("listener-key-v2-with-a-different-size")
    second = _new_client_handshake(str(key_path))

    assert fake_handshake.created == 2
    assert first.private_key is not second.private_key


def test_client_handshake_does_not_cache_missing_key(fake_handshake, tmp_path):
    missing = tmp_path / "missing.pem"

    first = _new_client_handshake(str(missing))
    second = _new_client_handshake(str(missing))

    assert fake_handshake.created == 2
    assert first.private_key is not second.private_key


# --- password-strength validation -----------------------------------------

def test_password_strength_is_checked_once_per_credential_revision(monkeypatch):
    checks = Mock()
    constructor_bits = []

    class FakePasswordHandshake:
        def __init__(self, password, min_bits):
            self.password = password
            constructor_bits.append(min_bits)

    monkeypatch.setattr(websocket_protocol, "runtime_password_min_bits", lambda: 40.0)
    monkeypatch.setattr(websocket_protocol, "check_password_strength", checks)
    monkeypatch.setattr(websocket_protocol, "PasswordHandShake", FakePasswordHandshake)

    first = _new_password_handshake("strong-machine-secret-v1")
    second = _new_password_handshake("strong-machine-secret-v1")
    rotated = _new_password_handshake("strong-machine-secret-v2")

    assert first is not second
    assert rotated.password.endswith("v2")
    assert checks.call_count == 2
    checks.assert_has_calls([
        call("strong-machine-secret-v1", min_bits=40.0),
        call("strong-machine-secret-v2", min_bits=40.0),
    ])
    assert constructor_bits == [0, 0, 0]
    assert all("strong-machine-secret" not in repr(key) for key in _PASSWORD_STRENGTH_CACHE)


def test_failed_password_strength_check_is_not_cached(monkeypatch):
    checks = Mock(side_effect=ValueError("weak"))
    monkeypatch.setattr(websocket_protocol, "runtime_password_min_bits", lambda: 40.0)
    monkeypatch.setattr(websocket_protocol, "check_password_strength", checks)

    for _ in range(2):
        with pytest.raises(ValueError, match="weak"):
            _new_password_handshake("weak")

    assert checks.call_count == 2


def test_password_strength_validation_is_serialized(monkeypatch):
    active = 0
    maximum_active = 0
    active_lock = threading.Lock()

    def non_thread_safe_validator(password, min_bits):
        nonlocal active, maximum_active
        with active_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.02)
        with active_lock:
            active -= 1

    monkeypatch.setattr(websocket_protocol, "runtime_password_min_bits", lambda: 40.0)
    monkeypatch.setattr(
        websocket_protocol,
        "check_password_strength",
        non_thread_safe_validator,
    )
    monkeypatch.setattr(
        websocket_protocol,
        "PasswordHandShake",
        lambda password, min_bits: SimpleNamespace(password=password),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        handshakes = list(
            executor.map(
                _new_password_handshake,
                [f"strong-machine-secret-{index}" for index in range(8)],
            )
        )

    assert maximum_active == 1
    assert len(handshakes) == 8


# --- websocket ping settings -----------------------------------------------

def test_websocket_ping_settings_default(monkeypatch):
    monkeypatch.delenv("HIVEMIND_WEBSOCKET_PING_INTERVAL", raising=False)
    monkeypatch.delenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT", raising=False)
    proto = HiveMindWebsocketProtocol(config={})

    assert proto._websocket_ping_settings() == {
        "websocket_ping_interval": DEFAULT_WEBSOCKET_PING_INTERVAL,
        "websocket_ping_timeout": DEFAULT_WEBSOCKET_PING_TIMEOUT,
    }


def test_websocket_ping_settings_from_env(monkeypatch):
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_INTERVAL", "25")
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT", "15")
    proto = HiveMindWebsocketProtocol(config={})

    assert proto._websocket_ping_settings() == {
        "websocket_ping_interval": 25.0,
        "websocket_ping_timeout": 15.0,
    }


def test_websocket_ping_settings_config_wins_over_env(monkeypatch):
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_INTERVAL", "25")
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT", "15")
    proto = HiveMindWebsocketProtocol(
        config={"websocket_ping_interval": 10, "websocket_ping_timeout": 5}
    )

    assert proto._websocket_ping_settings() == {
        "websocket_ping_interval": 10.0,
        "websocket_ping_timeout": 5.0,
    }


def test_websocket_ping_settings_invalid_values_fall_back(monkeypatch):
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_INTERVAL", "-1")
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT", "nope")
    proto = HiveMindWebsocketProtocol(config={})

    assert proto._websocket_ping_settings() == {
        "websocket_ping_interval": DEFAULT_WEBSOCKET_PING_INTERVAL,
        "websocket_ping_timeout": DEFAULT_WEBSOCKET_PING_TIMEOUT,
    }


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_websocket_ping_settings_non_finite_values_fall_back(monkeypatch, value):
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_INTERVAL", value)
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT", value)
    proto = HiveMindWebsocketProtocol(config={})

    assert proto._websocket_ping_settings() == {
        "websocket_ping_interval": DEFAULT_WEBSOCKET_PING_INTERVAL,
        "websocket_ping_timeout": DEFAULT_WEBSOCKET_PING_TIMEOUT,
    }


# --- open() auth path ------------------------------------------------------

def _auth_user(client_id=1, name="unit-client"):
    return SimpleNamespace(
        client_id=client_id,
        name=name,
        crypto_key=None,
        skill_blacklist=[],
        intent_blacklist=[],
        allowed_types=["recognizer_loop:utterance"],
        can_broadcast=True,
        can_propagate=True,
        can_escalate=True,
        is_admin=False,
        password=None,
    )


def _open_handler(db, key="api-key", seen_clients=None,
                  invalid_clients=None, closes=None):
    seen_clients = seen_clients if seen_clients is not None else []
    invalid_clients = invalid_clients if invalid_clients is not None else []
    closes = closes if closes is not None else []
    hm_protocol = SimpleNamespace(
        db=db,
        identity=SimpleNamespace(private_key=None),
        handshake_enabled=True,
        require_crypto=False,
        handle_new_client=seen_clients.append,
        handle_invalid_key_connected=invalid_clients.append,
        handle_invalid_protocol_version=lambda client: None,
    )

    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.hm_protocol = hm_protocol
    handler.request = SimpleNamespace(remote_ip="127.0.0.1", headers={})
    handler.application = SimpleNamespace(settings={})
    handler.loop = SimpleNamespace(
        add_callback=lambda callback, *args, **kwargs: callback(*args, **kwargs),
        run_in_executor=lambda executor, callback, *args: (
            asyncio.get_running_loop().run_in_executor(
                executor, callback, *args
            )
        ),
    )
    handler.write_message = lambda payload, is_bin=False: None
    handler.close = lambda *args, **kwargs: closes.append(
        {"args": args, "kwargs": kwargs}
    )
    handler.get_query_argument = lambda name, default=None: pybase64.b64encode(
        f"agent:{key}".encode()
    ).decode("ascii")
    return handler


def _run_open(handler):
    return asyncio.run(handler.open())


@pytest.fixture
def open_handler(monkeypatch):
    monkeypatch.setattr(
        websocket_protocol,
        "_new_client_handshake",
        lambda path: SimpleNamespace(),
    )
    return _open_handler


def test_open_schedules_downstream_writes_on_ioloop(open_handler):
    user = _auth_user()
    scheduled = []
    writes = []
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.loop = SimpleNamespace(
        add_callback=lambda callback, *args, **kwargs: scheduled.append(
            (callback, args, kwargs)
        )
    )
    handler.write_message = lambda payload, is_bin=False: writes.append(
        (payload, is_bin)
    )
    handler.event_loop_thread_id = None

    _run_open(handler)
    handler.client.send_msg("payload", True)

    assert writes == []
    assert len(scheduled) == 1
    callback, args, kwargs = scheduled.pop()
    callback(*args, **kwargs)
    assert writes == [("payload", True)]


def test_open_writes_downstream_frames_directly_on_ioloop_thread(open_handler):
    user = _auth_user()
    writes = []
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.event_loop_thread_id = threading.get_ident()
    handler.loop = SimpleNamespace(
        add_callback=Mock(side_effect=AssertionError("queued an IOLoop write")),
    )
    handler.write_message = lambda payload, is_bin=False: writes.append(
        (payload, is_bin)
    )

    _run_open(handler)
    handler.client.send_msg("payload", True)

    assert writes == [("payload", True)]
    handler.loop.add_callback.assert_not_called()


def test_open_uses_direct_api_key_lookup_without_sync(open_handler):
    user = _auth_user()

    def fail_sync():
        raise AssertionError("db.sync must not run for a cached API key")

    seen_clients = []
    db = SimpleNamespace(
        db=object(),
        sync=fail_sync,
        get_client_by_api_key=lambda key: user if key == "api-key" else None,
    )
    handler = open_handler(db, seen_clients=seen_clients)

    _run_open(handler)

    assert len(seen_clients) == 1


def test_open_seeds_core_resolved_user_cache(open_handler, monkeypatch):
    user = _auth_user()
    cached = []
    monkeypatch.setattr(
        websocket_protocol.HiveMindClientConnection,
        "cache_resolved_user",
        lambda client, resolved: cached.append((client, resolved)),
        raising=False,
    )
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )

    _run_open(handler)

    assert cached == [(handler.client, user)]


def test_open_syncs_local_database_once_after_api_key_miss(open_handler):
    user = _auth_user(client_id=2, name="fresh-client")
    state = {"synced": False, "syncs": 0}

    def sync():
        state["syncs"] += 1
        state["synced"] = True

    def lookup(key):
        if key == "fresh-key" and state["synced"]:
            return user
        return None

    seen_clients = []
    db = SimpleNamespace(db=object(), sync=sync, get_client_by_api_key=lookup)
    handler = open_handler(db, key="fresh-key", seen_clients=seen_clients)

    _run_open(handler)

    assert state["syncs"] == 1
    assert len(seen_clients) == 1


def test_open_never_syncs_remote_database(open_handler):
    sync = Mock(side_effect=AssertionError("remote sync entered WSS auth path"))
    invalid_clients = []
    db = SimpleNamespace(
        db=Mock(spec=AbstractRemoteDB),
        sync=sync,
        get_client_by_api_key=lambda key: None,
    )
    handler = open_handler(db, invalid_clients=invalid_clients)

    _run_open(handler)

    sync.assert_not_called()
    assert len(invalid_clients) == 1


def test_open_runs_remote_api_key_lookups_concurrently(open_handler):
    user = _auth_user()

    def lookup(key):
        time.sleep(0.05)
        return user

    db = SimpleNamespace(
        db=Mock(spec=AbstractRemoteDB),
        get_client_by_api_key=lookup,
    )
    handlers = [open_handler(db, seen_clients=[]) for _ in range(8)]

    async def run_all():
        await asyncio.gather(*(handler.open() for handler in handlers))

    started = time.monotonic()
    asyncio.run(run_all())
    elapsed = time.monotonic() - started

    assert elapsed < 0.25


def test_open_keeps_password_validation_off_event_loop(open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"

    def build_handshake(password, min_bits):
        time.sleep(0.05)
        return SimpleNamespace(password=password, min_bits=min_bits)

    monkeypatch.setattr(websocket_protocol, "_new_password_handshake", build_handshake)
    db = SimpleNamespace(get_client_by_api_key=lambda key: user)
    handlers = [open_handler(db, seen_clients=[]) for _ in range(8)]
    for handler in handlers:
        handler.password_min_bits = 40.0

    async def run_all():
        await asyncio.gather(*(handler.open() for handler in handlers))

    started = time.monotonic()
    asyncio.run(run_all())
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert all(handler.client.pswd_handshake.password == user.password for handler in handlers)
    assert all(handler.client.pswd_handshake.min_bits == 40.0 for handler in handlers)


def test_open_skips_password_strength_check_when_preshared_key_is_preferred(
        open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    user.crypto_key = "0123456789abcdef"
    password_handshake = SimpleNamespace(password=user.password)
    build_handshake = Mock(return_value=password_handshake)
    monkeypatch.setattr(
        websocket_protocol,
        "_new_password_handshake",
        build_handshake,
    )
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.prefer_preshared_key = True

    caller_thread = threading.get_ident()
    handshake_threads = []
    build_handshake.side_effect = lambda *_args: (
        handshake_threads.append(threading.get_ident()) or password_handshake
    )

    _run_open(handler)

    assert handler.client.crypto_key == user.crypto_key
    assert handler.client.pswd_handshake is password_handshake
    build_handshake.assert_called_once_with(user.password, 0.0)
    assert handshake_threads == [caller_thread]


def test_open_keeps_password_handshake_without_preshared_key(
        open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    build_handshake = Mock(
        return_value=SimpleNamespace(password=user.password),
    )
    monkeypatch.setattr(
        websocket_protocol,
        "_new_password_handshake",
        build_handshake,
    )
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.prefer_preshared_key = True

    _run_open(handler)

    build_handshake.assert_called_once_with(user.password, None)
    assert handler.client.pswd_handshake.password == user.password


def test_open_logs_credential_free_slow_admission_timings(
        open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    info = Mock()
    monkeypatch.setattr(websocket_protocol.LOG, "info", info)
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.slow_admission_log_ms = 0

    _run_open(handler)

    message = info.call_args.args[0]
    assert "lookup_ms=" in message
    assert "password_ms=" in message
    assert "protocol_ms=" in message
    assert "total_ms=" in message
    assert "preshared_key=False" in message
    assert "api-key" not in message
    assert user.password not in message


def test_prefer_preshared_key_is_default_and_config_overrides_env(monkeypatch):
    proto = HiveMindWebsocketProtocol(config={})
    assert proto._prefer_preshared_key() is True

    monkeypatch.setenv("HIVEMIND_WEBSOCKET_PREFER_PRESHARED_KEY", "false")
    assert proto._prefer_preshared_key() is False
    assert HiveMindWebsocketProtocol(
        config={"prefer_preshared_key": True},
    )._prefer_preshared_key() is True


def test_slow_admission_log_threshold_config_overrides_env(monkeypatch):
    proto = HiveMindWebsocketProtocol(config={})
    assert proto._slow_admission_log_ms() == DEFAULT_SLOW_ADMISSION_LOG_MS

    monkeypatch.setenv("HIVEMIND_WEBSOCKET_SLOW_ADMISSION_LOG_MS", "125")
    assert proto._slow_admission_log_ms() == 125.0
    assert HiveMindWebsocketProtocol(
        config={"slow_admission_log_ms": 250},
    )._slow_admission_log_ms() == 250.0


def test_inbound_executor_settings_default_and_config_overrides_env(monkeypatch):
    proto = HiveMindWebsocketProtocol(config={})
    assert proto._inbound_executor_settings() == (
        DEFAULT_INBOUND_EXECUTOR_WORKERS,
        DEFAULT_INBOUND_QUEUE_SIZE,
        DEFAULT_INBOUND_CLIENT_QUEUE_SIZE,
    )

    monkeypatch.setenv("HIVEMIND_WEBSOCKET_INBOUND_EXECUTOR_WORKERS", "8")
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_INBOUND_QUEUE_SIZE", "512")
    monkeypatch.setenv("HIVEMIND_WEBSOCKET_INBOUND_CLIENT_QUEUE_SIZE", "32")
    assert proto._inbound_executor_settings() == (8, 512, 32)
    assert HiveMindWebsocketProtocol(config={
        "inbound_executor_workers": 12,
        "inbound_queue_size": 768,
        "inbound_client_queue_size": 48,
    })._inbound_executor_settings() == (12, 768, 48)


def test_open_isolates_remote_auth_from_password_handshake(open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    auth_executor = object()
    handshake_executor = object()
    calls = []
    db = SimpleNamespace(
        db=Mock(spec=AbstractRemoteDB),
        get_client_by_api_key=lambda key: user,
    )
    handler = open_handler(db, seen_clients=[])
    handler.auth_executor = auth_executor
    handler.handshake_executor = handshake_executor
    handler.password_min_bits = 40.0

    async def run_in_executor(executor, callback, *args):
        calls.append((executor, callback))
        return callback(*args)

    handler.loop = SimpleNamespace(
        add_callback=lambda callback, *args, **kwargs: callback(*args, **kwargs),
        run_in_executor=run_in_executor,
    )
    monkeypatch.setattr(
        websocket_protocol,
        "_new_password_handshake",
        lambda password, min_bits: SimpleNamespace(
            password=password,
            min_bits=min_bits,
        ),
    )

    _run_open(handler)

    assert calls == [
        (auth_executor, db.get_client_by_api_key),
        (handshake_executor, websocket_protocol._new_password_handshake),
        (auth_executor, handler.hm_protocol.handle_new_client),
    ]


def test_open_uses_startup_password_policy_snapshot(open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.password_min_bits = 0.0
    monkeypatch.setattr(
        websocket_protocol,
        "runtime_password_min_bits",
        lambda: (_ for _ in ()).throw(
            AssertionError("connection hot path re-read server config")
        ),
    )

    _run_open(handler)

    assert handler.client.pswd_handshake.password == user.password


def test_executor_worker_defaults_cover_guarded_admission_burst():
    assert DEFAULT_AUTH_EXECUTOR_WORKERS >= 50
    assert DEFAULT_HANDSHAKE_EXECUTOR_WORKERS >= 25
    assert DEFAULT_INBOUND_EXECUTOR_WORKERS >= 8
    assert DEFAULT_INBOUND_QUEUE_SIZE >= 400
    assert DEFAULT_INBOUND_CLIENT_QUEUE_SIZE >= 16
    assert DEFAULT_CONNECT_LIFECYCLE_EXECUTOR_WORKERS >= 8
    assert DEFAULT_DISCONNECT_EXECUTOR_WORKERS == 1


def test_open_runs_admission_callbacks_concurrently(open_handler):
    user = _auth_user()
    seen_clients = []

    def slow_admission(client):
        time.sleep(0.05)
        seen_clients.append(client)

    handlers = [
        open_handler(
            SimpleNamespace(get_client_by_api_key=lambda key: user),
            seen_clients=[],
        )
        for _ in range(8)
    ]
    for handler in handlers:
        handler.hm_protocol.handle_new_client = slow_admission

    async def run_all():
        await asyncio.gather(*(handler.open() for handler in handlers))

    started = time.monotonic()
    asyncio.run(run_all())
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert len(seen_clients) == 8


def test_open_returns_before_blocking_connect_lifecycle(open_handler):
    user = _auth_user()
    lifecycle_started = threading.Event()
    release_lifecycle = threading.Event()
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    protocol_clients = []
    lifecycle_clients = []

    def initialize_protocol(client):
        protocol_clients.append(client)
        return True

    def publish_lifecycle(client):
        lifecycle_started.set()
        release_lifecycle.wait(1)
        lifecycle_clients.append(client)

    handler.hm_protocol.handle_new_client_protocol = initialize_protocol
    handler.hm_protocol.handle_client_connected = publish_lifecycle
    lifecycle_executor = ThreadPoolExecutor(max_workers=1)
    handler.connect_lifecycle_executor = lifecycle_executor

    try:
        started = time.monotonic()
        _run_open(handler)
        elapsed = time.monotonic() - started

        assert elapsed < 0.25
        assert lifecycle_started.wait(1)
        assert protocol_clients == [handler.client]
        assert lifecycle_clients == []
    finally:
        release_lifecycle.set()
        lifecycle_executor.shutdown(wait=True)

    assert lifecycle_clients == [handler.client]


def test_open_writes_cache_guarded_frames_on_event_loop(
        open_handler, monkeypatch):
    user = _auth_user()
    user.password = "strong-machine-secret"
    user.crypto_key = "0123456789abcdef"
    monkeypatch.setattr(
        websocket_protocol.HiveMindClientConnection,
        "cache_resolved_user",
        lambda client, resolved: setattr(client, "_resolved_user", resolved),
        raising=False,
    )
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )
    handler.prefer_preshared_key = True
    protocol_threads = []
    protocol_writes = []
    executor_protocol = Mock(return_value=True)
    cached_protocol = Mock(
        side_effect=lambda client: (
            protocol_threads.append(threading.get_ident())
            or client.send_msg("handshake-frame", False)
            or True
        ),
    )
    handler.hm_protocol.handle_new_client_protocol = executor_protocol
    handler.hm_protocol.handle_new_client_protocol_cached = cached_protocol
    handler.hm_protocol.handle_client_connected = Mock()
    lifecycle_executor = ThreadPoolExecutor(max_workers=1)
    handler.connect_lifecycle_executor = lifecycle_executor
    caller_thread = threading.get_ident()
    handler.event_loop_thread_id = caller_thread
    handler.write_message = lambda payload, is_bin=False: protocol_writes.append(
        (payload, is_bin)
    )

    try:
        _run_open(handler)
    finally:
        lifecycle_executor.shutdown(wait=True)

    cached_protocol.assert_called_once_with(handler.client)
    executor_protocol.assert_not_called()
    assert len(protocol_threads) == 1
    assert protocol_threads[0] == caller_thread
    assert protocol_writes == [("handshake-frame", False)]


def test_cached_protocol_burst_avoids_executor_completion_queue(
        open_handler, monkeypatch):
    user = _auth_user()
    monkeypatch.setattr(
        websocket_protocol.HiveMindClientConnection,
        "cache_resolved_user",
        lambda client, resolved: setattr(client, "_resolved_user", resolved),
        raising=False,
    )
    handlers = [
        open_handler(
            SimpleNamespace(get_client_by_api_key=lambda key: user),
            seen_clients=[],
        )
        for _ in range(8)
    ]
    lifecycle_executor = ThreadPoolExecutor(max_workers=8)
    lifecycle_barrier = threading.Barrier(9)

    def cached_protocol(client):
        client.send_msg("handshake-frame", False)
        return True

    for handler in handlers:
        handler.hm_protocol.handle_new_client_protocol = Mock(return_value=True)
        handler.hm_protocol.handle_new_client_protocol_cached = cached_protocol
        handler.hm_protocol.handle_client_connected = (
            lambda _client: lifecycle_barrier.wait(timeout=1)
        )
        handler.connect_lifecycle_executor = lifecycle_executor

    async def run_all():
        await asyncio.gather(*(handler.open() for handler in handlers))

    try:
        asyncio.run(run_all())
        lifecycle_barrier.wait(timeout=1)
    finally:
        lifecycle_barrier.abort()
        lifecycle_executor.shutdown(wait=True)


def test_close_waits_for_matching_connect_lifecycle(open_handler):
    user = _auth_user()
    lifecycle_started = threading.Event()
    release_lifecycle = threading.Event()
    disconnect_finished = threading.Event()
    events = []
    handler = open_handler(
        SimpleNamespace(get_client_by_api_key=lambda key: user),
        seen_clients=[],
    )

    handler.hm_protocol.handle_new_client_protocol = lambda _client: True

    def publish_lifecycle(_client):
        events.append("connect-start")
        lifecycle_started.set()
        release_lifecycle.wait(1)
        events.append("connect-finish")

    def publish_disconnect(_client):
        events.append("disconnect")
        disconnect_finished.set()

    handler.hm_protocol.handle_client_connected = publish_lifecycle
    handler.hm_protocol.handle_client_disconnected = publish_disconnect
    lifecycle_executor = ThreadPoolExecutor(max_workers=1)
    disconnect_executor = ThreadPoolExecutor(max_workers=1)
    handler.connect_lifecycle_executor = lifecycle_executor
    handler.disconnect_executor = disconnect_executor

    try:
        _run_open(handler)
        assert lifecycle_started.wait(1)

        handler.on_close()
        handler.on_close()
        assert not disconnect_finished.wait(0.05)
        release_lifecycle.set()
        assert disconnect_finished.wait(1)
    finally:
        release_lifecycle.set()
        lifecycle_executor.shutdown(wait=True)
        disconnect_executor.shutdown(wait=True)

    assert events == ["connect-start", "connect-finish", "disconnect"]


def test_close_defers_ordered_disconnect_callbacks_off_event_loop():
    calls = []
    first_finished = threading.Event()
    second_finished = threading.Event()

    def disconnect(client):
        calls.append(("start", client.peer))
        time.sleep(0.05)
        calls.append(("finish", client.peer))
        (first_finished if client.peer == "first" else second_finished).set()

    protocol = SimpleNamespace(handle_client_disconnected=disconnect)
    handlers = []
    with ThreadPoolExecutor(max_workers=1) as executor:
        for peer in ("first", "second"):
            handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
            handler.hm_protocol = protocol
            handler.disconnect_executor = executor
            handler.client = SimpleNamespace(peer=peer)
            handler.source_ip = "127.0.0.1"
            handler.request = SimpleNamespace(remote_ip="127.0.0.1")
            handlers.append(handler)

        started = time.monotonic()
        handlers[0].on_close()
        handlers[1].on_close()
        elapsed = time.monotonic() - started

        assert elapsed < 0.03
        assert first_finished.wait(1)
        assert second_finished.wait(1)

    assert calls == [
        ("start", "first"),
        ("finish", "first"),
        ("start", "second"),
        ("finish", "second"),
    ]


def test_close_retains_embedded_handler_fallback_without_executor():
    disconnected = []
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    handler.hm_protocol = SimpleNamespace(
        handle_client_disconnected=disconnected.append,
    )
    handler.disconnect_executor = None
    handler.client = SimpleNamespace(peer="embedded")
    handler.source_ip = "127.0.0.1"
    handler.request = SimpleNamespace(remote_ip="127.0.0.1")

    handler.on_close()

    assert disconnected == [handler.client]


def test_close_cancels_abandoned_authorization_work():
    handler = HiveMindTornadoWebSocket.__new__(HiveMindTornadoWebSocket)
    auth_lookup = Mock()
    auth_lookup.done.return_value = False
    auth_task = Mock()
    auth_task.done.return_value = False
    handler._auth_lookup_future = auth_lookup
    handler._auth_task = auth_task
    handler._auth_admission_reserved = False
    handler._client_admitted = False
    handler.request = SimpleNamespace(remote_ip="127.0.0.1")

    handler.on_close()

    auth_lookup.cancel.assert_called_once_with()
    auth_task.cancel.assert_called_once_with()


def test_open_fails_closed_when_remote_lookup_raises(open_handler):
    closes = []
    db = SimpleNamespace(
        db=Mock(spec=AbstractRemoteDB),
        get_client_by_api_key=Mock(
            side_effect=RuntimeError("database unavailable")
        ),
    )
    handler = open_handler(db, closes=closes)

    _run_open(handler)

    assert closes[-1]["kwargs"] == {
        "code": 1011,
        "reason": "client database unavailable",
    }


def test_open_reports_local_sync_failure_as_server_error(open_handler):
    def fail_sync():
        raise RuntimeError("database unavailable")

    closes = []
    db = SimpleNamespace(
        db=object(),
        sync=fail_sync,
        get_client_by_api_key=lambda key: None,
    )
    handler = open_handler(db, closes=closes)

    _run_open(handler)

    assert closes[-1]["kwargs"] == {
        "code": 1011,
        "reason": "client database unavailable",
    }


def test_open_debounces_repeated_local_sync_misses(open_handler, monkeypatch):
    monkeypatch.setattr(HiveMindTornadoWebSocket, "_sync_debounce_s", 60.0)
    state = {"syncs": 0}

    def sync():
        state["syncs"] += 1

    db = SimpleNamespace(
        db=object(),
        sync=sync,
        get_client_by_api_key=lambda key: None,
    )

    _run_open(open_handler(db, key="missing-a"))
    _run_open(open_handler(db, key="missing-b"))

    assert state["syncs"] == 1


def test_open_debounces_repeated_local_sync_failures(open_handler, monkeypatch):
    monkeypatch.setattr(HiveMindTornadoWebSocket, "_sync_debounce_s", 60.0)
    state = {"syncs": 0}
    closes = []

    def fail_sync():
        state["syncs"] += 1
        raise RuntimeError("database unavailable")

    db = SimpleNamespace(
        db=object(),
        sync=fail_sync,
        get_client_by_api_key=lambda key: None,
    )

    _run_open(open_handler(db, closes=closes))
    _run_open(open_handler(db, closes=closes))

    assert state["syncs"] == 1
    assert [close["kwargs"]["code"] for close in closes] == [1011, 1011]


# --- self-signed cert generation ------------------------------------------

def test_create_self_signed_cert_writes_files(tmp_path):
    cert, key = HiveMindWebsocketProtocol.create_self_signed_cert(
        cert_dir=str(tmp_path), name="hwp-test"
    )
    assert Path(cert).exists()
    assert Path(key).exists()
    assert Path(cert).read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" in Path(key).read_bytes()


def test_create_self_signed_cert_idempotent(tmp_path):
    """Second call with the same dir/name reuses the existing files."""
    c1, k1 = HiveMindWebsocketProtocol.create_self_signed_cert(
        cert_dir=str(tmp_path), name="hwp-test"
    )
    mtime = os.path.getmtime(c1)
    # Sleep so a rewrite would change the mtime.
    time.sleep(0.05)
    c2, k2 = HiveMindWebsocketProtocol.create_self_signed_cert(
        cert_dir=str(tmp_path), name="hwp-test"
    )
    assert c1 == c2 and k1 == k2
    assert os.path.getmtime(c1) == mtime, "should not have been rewritten"


# --- run() lifecycle -------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_run_starts_and_serves_on_plain_ws():
    """Calling proto.run() binds and services a real websocket upgrade."""
    master = MasterNode.create("MX", require_crypto=False, handshake_enabled=True)
    port = _free_port()
    proto = HiveMindWebsocketProtocol(
        config={"host": "127.0.0.1", "port": port, "ssl": False},
        hm_protocol=master.hm_protocol,
    )

    # Earlier tests (tornado_server fixture) leave a stale class-level loop
    # reference pointing at a stopped loop. Clear it so our polling loop
    # only signals on a fresh one.
    if hasattr(HiveMindTornadoWebSocket, "loop"):
        del HiveMindTornadoWebSocket.loop

    started = threading.Event()

    def _run():
        started.set()
        proto.run()

    def _wait_for_loop():
        for _ in range(200):
            loop = getattr(HiveMindTornadoWebSocket, "loop", None)
            if loop is not None and getattr(loop, "asyncio_loop", None) is not None:
                return loop
            time.sleep(0.05)
        raise AssertionError("run() did not install a Tornado IOLoop")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert started.wait(2)
    loop = _wait_for_loop()

    s = socket.socket()
    try:
        s.settimeout(1)
        s.connect(("127.0.0.1", port))
        s.sendall(
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        assert b"101 Switching Protocols" in s.recv(512)
    finally:
        s.close()
        loop.add_callback(loop.stop)

    t.join(timeout=5)
    assert not t.is_alive(), "run() did not return after ioloop.stop()"


def test_run_raises_when_listener_bind_fails():
    """Bind failures propagate instead of looking like clean exits."""
    master = MasterNode.create("MF", require_crypto=False, handshake_enabled=True)
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    proto = HiveMindWebsocketProtocol(
        config={"host": "127.0.0.1", "port": port, "ssl": False},
        hm_protocol=master.hm_protocol,
    )
    if hasattr(HiveMindTornadoWebSocket, "loop"):
        del HiveMindTornadoWebSocket.loop

    try:
        with pytest.raises(OSError):
            proto.run()
    finally:
        blocker.close()


def test_run_ssl_path_uses_existing_cert(tmp_path):
    """SSL branch in run(): existing cert is picked up; no regeneration."""
    _cert, _key = HiveMindWebsocketProtocol.create_self_signed_cert(
        cert_dir=str(tmp_path), name="ssl-test"
    )
    master = MasterNode.create("MS", require_crypto=False, handshake_enabled=True)
    port = _free_port()
    proto = HiveMindWebsocketProtocol(
        config={"host": "127.0.0.1", "port": port, "ssl": True,
                "cert_dir": str(tmp_path), "cert_name": "ssl-test"},
        hm_protocol=master.hm_protocol,
    )
    if hasattr(HiveMindTornadoWebSocket, "loop"):
        del HiveMindTornadoWebSocket.loop

    started = threading.Event()

    def _stop_when_ready():
        for _ in range(200):
            loop = getattr(HiveMindTornadoWebSocket, "loop", None)
            if loop is not None and getattr(loop, "asyncio_loop", None) is not None:
                time.sleep(0.1)
                loop.add_callback(loop.stop)
                return
            time.sleep(0.05)

    def _run():
        threading.Thread(target=_stop_when_ready, daemon=True).start()
        started.set()
        proto.run()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert started.wait(2)
    t.join(timeout=5)
    assert not t.is_alive()


def test_run_ssl_path_generates_missing_cert(tmp_path):
    """SSL branch in run(): if cert/key are missing, they're generated."""
    master = MasterNode.create("MS2", require_crypto=False, handshake_enabled=True)
    port = _free_port()
    cert_dir = tmp_path / "fresh"
    proto = HiveMindWebsocketProtocol(
        config={"host": "127.0.0.1", "port": port, "ssl": True,
                "cert_dir": str(cert_dir), "cert_name": "gen-me"},
        hm_protocol=master.hm_protocol,
    )
    if hasattr(HiveMindTornadoWebSocket, "loop"):
        del HiveMindTornadoWebSocket.loop

    started = threading.Event()

    def _stop_when_ready():
        for _ in range(200):
            loop = getattr(HiveMindTornadoWebSocket, "loop", None)
            if loop is not None and getattr(loop, "asyncio_loop", None) is not None:
                time.sleep(0.1)
                loop.add_callback(loop.stop)
                return
            time.sleep(0.05)

    def _run():
        threading.Thread(target=_stop_when_ready, daemon=True).start()
        started.set()
        proto.run()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert started.wait(2)
    t.join(timeout=5)
    assert not t.is_alive()
    assert (cert_dir / "gen-me.crt").exists()
    assert (cert_dir / "gen-me.key").exists()
