"""Shared fixtures for end-to-end tests.

Two flavours:

- `hive`: hivescope's in-process shim — fast, used for assertions about the
  HiveMind listener protocol's routing logic (binary frames, broadcast, etc).
- `tornado_server`: spins up the *actual* HiveMindWebsocketProtocol (Tornado
  on a real port) and yields connection info. Tests that need to exercise
  the websocket transport itself (auth via query string, real frames over
  the wire, on_close cleanup) use this fixture and connect via
  `HiveMessageBusClient`.
"""
import socket
import threading
import time
from dataclasses import dataclass

import pytest
from tornado import ioloop

from hivemind_websocket_protocol import HiveMindTornadoWebSocket
from hivescope.node import MasterNode
from hivescope.scenarios import single_satellite


# ---------------------------------------------------------------------------
# In-process (fast) — for routing/protocol assertions
# ---------------------------------------------------------------------------

@pytest.fixture
def hive():
    """A started single-satellite topology; teardown is automatic.

    Yields `(master, satellite)` for the standard M0/S0 pair.
    """
    builder = single_satellite()
    try:
        builder.start_all()
        yield builder.get_master("M0"), builder.get_satellite("S0")
    finally:
        builder.stop_all()


# ---------------------------------------------------------------------------
# Real Tornado — for transport assertions
# ---------------------------------------------------------------------------

@dataclass
class TornadoServer:
    host: str
    port: int
    api_key: str
    password: str
    master: MasterNode  # provides .hm_protocol, .recorder, .db, etc.

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}"

    @property
    def listener(self):
        return self.master.hm_protocol


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn_tornado(trusted_networks=(), trusted_headers=()):
    """Helper: spin up HiveMindWebsocketProtocol on a real Tornado server.

    Returns `(TornadoServer, thread, loop)`. Caller is responsible for
    teardown via `_teardown_tornado(thread, loop)`.
    """
    api_key = "test-api-key"
    password = "test-password"

    master = MasterNode.create("M0", require_crypto=False, handshake_enabled=True)
    master.register_satellite(
        api_key,
        password=password,
        allowed_types=[
            "recognizer_loop:utterance",
            "recognizer_loop:b64_audio",
            "speak",
        ],
    )

    port = _free_port()
    server_ready = threading.Event()
    server_error = []
    loop_ref = []

    def _run():
        try:
            import asyncio
            from tornado import web
            from tornado.platform.asyncio import AnyThreadEventLoopPolicy
            asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
            loop = ioloop.IOLoop()
            loop.make_current()
            loop_ref.append(loop)
            HiveMindTornadoWebSocket.loop = loop
            HiveMindTornadoWebSocket.hm_protocol = master.hm_protocol
            app = web.Application(
                [("/", HiveMindTornadoWebSocket)],
                trusted_networks=trusted_networks,
                trusted_headers=trusted_headers,
            )
            app.listen(port, "127.0.0.1")
            loop.add_callback(server_ready.set)
            loop.start()
        except Exception as exc:
            server_error.append(exc)
            server_ready.set()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    if not server_ready.wait(timeout=5.0):
        raise RuntimeError("Tornado server failed to start within 5s")
    if server_error:
        raise server_error[0]
    time.sleep(0.05)
    server = TornadoServer(host="127.0.0.1", port=port,
                           api_key=api_key, password=password, master=master)
    return server, thread, loop_ref[0]


def _teardown_tornado(thread, loop):
    """Stop the specific IOLoop this spawn created and join its thread."""
    if loop is not None:
        loop.add_callback(loop.stop)
    thread.join(timeout=5.0)


@pytest.fixture
def tornado_server():
    """Plain Tornado server, no trusted-proxy config."""
    server, thread, loop = _spawn_tornado()
    try:
        yield server
    finally:
        _teardown_tornado(thread, loop)


@pytest.fixture
def tornado_server_with_proxy():
    """Tornado server with 127.0.0.0/8 as a trusted proxy CIDR.

    Tests use this to send X-Forwarded-For / X-Real-IP from the local
    client (which IS in 127.0.0.0/8) and assert the listener resolves
    the forwarded address.
    """
    from hivemind_websocket_protocol._client_ip import parse_networks
    networks = parse_networks(["127.0.0.0/8"])
    headers = ("x-forwarded-for", "x-real-ip")
    server, thread, loop = _spawn_tornado(
        trusted_networks=networks, trusted_headers=headers,
    )
    try:
        yield server
    finally:
        _teardown_tornado(thread, loop)
