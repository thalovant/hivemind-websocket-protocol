"""Unit-level coverage for the bits e2e tests don't reach directly.

Targets:
- `HiveMindWebsocketProtocol.run()` for the plain (ssl=False) path,
  including the actual `application.listen()` call.
- `create_self_signed_cert()` certificate / key generation.
- version.py module loading.
"""
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from hivemind_plugin_manager.database import AbstractRemoteDB

from hivemind_websocket_protocol import (
    DEFAULT_WEBSOCKET_PING_INTERVAL,
    DEFAULT_WEBSOCKET_PING_TIMEOUT,
    _HANDSHAKE_TEMPLATE_CACHE,
    HiveMindTornadoWebSocket,
    HiveMindWebsocketProtocol,
    _new_client_handshake,
    _refresh_local_client_database,
)
import hivemind_websocket_protocol as websocket_protocol
from hivescope.node import MasterNode


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
