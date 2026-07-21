"""Unit-level coverage for the bits e2e tests don't reach directly.

Targets:
- `HiveMindWebsocketProtocol.run()` for the plain (ssl=False) path,
  including the actual `application.listen()` call.
- `create_self_signed_cert()` certificate / key generation.
- version.py module loading.
"""
import asyncio
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
from tornado.websocket import WebSocketClosedError

from hivemind_websocket_protocol import (
    DEFAULT_AUTH_EXECUTOR_WORKERS,
    DEFAULT_HANDSHAKE_EXECUTOR_WORKERS,
    DEFAULT_WEBSOCKET_PING_INTERVAL,
    DEFAULT_WEBSOCKET_PING_TIMEOUT,
    _HANDSHAKE_TEMPLATE_CACHE,
    _PASSWORD_STRENGTH_CACHE,
    HiveMindTornadoWebSocket,
    HiveMindWebsocketProtocol,
    _finish_websocket_write,
    _new_client_handshake,
    _new_password_handshake,
    _refresh_local_client_database,
    _write_websocket_message,
)
import hivemind_websocket_protocol as websocket_protocol
from hivescope.node import MasterNode


@pytest.fixture(autouse=True)
def _reset_websocket_sync_state():
    HiveMindTornadoWebSocket._last_sync_ts = 0.0
    HiveMindTornadoWebSocket._last_sync_error = None
    _PASSWORD_STRENGTH_CACHE.clear()
    yield
    _PASSWORD_STRENGTH_CACHE.clear()


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


def test_password_handshakes_are_processed_concurrently_off_event_loop():
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

    async def run_all():
        await asyncio.gather(*(handler.on_message("payload") for handler in handlers))

    started = time.monotonic()
    asyncio.run(run_all())
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert len(handled) == 8


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
        f"agent:{key}".encode("utf-8")
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

    _run_open(handler)
    handler.client.send_msg("payload", True)

    assert writes == []
    assert len(scheduled) == 1
    callback, args, kwargs = scheduled.pop()
    callback(*args, **kwargs)
    assert writes == [("payload", True)]


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

    def build_handshake(password):
        time.sleep(0.05)
        return SimpleNamespace(password=password)

    monkeypatch.setattr(websocket_protocol, "_new_password_handshake", build_handshake)
    db = SimpleNamespace(get_client_by_api_key=lambda key: user)
    handlers = [open_handler(db, seen_clients=[]) for _ in range(8)]

    async def run_all():
        await asyncio.gather(*(handler.open() for handler in handlers))

    started = time.monotonic()
    asyncio.run(run_all())
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert all(handler.client.pswd_handshake.password == user.password for handler in handlers)


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
        lambda password: SimpleNamespace(password=password),
    )

    _run_open(handler)

    assert calls == [
        (auth_executor, db.get_client_by_api_key),
        (handshake_executor, websocket_protocol._new_password_handshake),
    ]


def test_executor_worker_defaults_cover_guarded_admission_burst():
    assert DEFAULT_AUTH_EXECUTOR_WORKERS >= 50
    assert DEFAULT_HANDSHAKE_EXECUTOR_WORKERS >= 25


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
    cert, key = HiveMindWebsocketProtocol.create_self_signed_cert(
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
