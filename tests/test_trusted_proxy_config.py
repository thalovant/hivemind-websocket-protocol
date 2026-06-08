"""Integration tests for trusted-proxy config loading in run().

Exercises the precedence rules:
- config dict key takes precedence over env var
- env var takes precedence over default
- explicit empty config list disables the feature (regression for the
  `or`-vs-`in self.config` fix)
"""
import asyncio
import threading
import time

from tornado.platform.asyncio import AnyThreadEventLoopPolicy

from hivemind_websocket_protocol import (
    HiveMindTornadoWebSocket,
    HiveMindWebsocketProtocol,
)
from hivescope.node import MasterNode

from tests.test_protocol_unit import _free_port


def _run_until_settings_loaded(proto):
    """Start proto.run() in a thread, wait for the Application to install
    its settings, then stop the loop and return the settings dict."""
    if hasattr(HiveMindTornadoWebSocket, "loop"):
        del HiveMindTornadoWebSocket.loop

    started = threading.Event()
    captured = {}

    def _stop_when_ready():
        for _ in range(200):
            loop = getattr(HiveMindTornadoWebSocket, "loop", None)
            if loop is not None and getattr(loop, "asyncio_loop", None) is not None:
                # The Application is constructed inside run() right before
                # listen(). Pull settings from the handler's first registered
                # app.  We grab it indirectly via the listening HTTPServer.
                time.sleep(0.1)
                loop.add_callback(loop.stop)
                return
            time.sleep(0.05)

    def _run():
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        threading.Thread(target=_stop_when_ready, daemon=True).start()
        started.set()
        # Hook into run() — we replace web.Application.listen with a recorder.
        from tornado import web
        original_init = web.Application.__init__

        def _spy_init(self, *args, **kwargs):
            captured.update(kwargs)
            return original_init(self, *args, **kwargs)

        web.Application.__init__ = _spy_init
        try:
            proto.run()
        finally:
            web.Application.__init__ = original_init

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert started.wait(2)
    t.join(timeout=5)
    return captured


def _make_proto(config=None):
    master = MasterNode.create("MC", require_crypto=False, handshake_enabled=True)
    cfg = {"host": "127.0.0.1", "port": _free_port(), "ssl": False}
    if config:
        cfg.update(config)
    return HiveMindWebsocketProtocol(config=cfg, hm_protocol=master.hm_protocol)


# --- precedence rules ----------------------------------------------------

def test_config_proxy_cidrs_overrides_env(monkeypatch):
    monkeypatch.setenv("HIVEMIND_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    proto = _make_proto({"trusted_proxy_cidrs": "192.168.0.0/16"})
    settings = _run_until_settings_loaded(proto)
    networks = settings["trusted_networks"]
    assert len(networks) == 1
    assert str(networks[0]) == "192.168.0.0/16"


def test_env_used_when_config_absent(monkeypatch):
    monkeypatch.setenv("HIVEMIND_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,172.16.0.0/12")
    proto = _make_proto()
    settings = _run_until_settings_loaded(proto)
    assert len(settings["trusted_networks"]) == 2


def test_explicit_empty_config_disables_feature(monkeypatch):
    """Regression: 'or' would have leaked env into an explicit empty list."""
    monkeypatch.setenv("HIVEMIND_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    proto = _make_proto({"trusted_proxy_cidrs": []})
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_networks"] == ()


def test_default_headers_used_when_nothing_configured(monkeypatch):
    monkeypatch.delenv("HIVEMIND_TRUSTED_CLIENT_IP_HEADERS", raising=False)
    monkeypatch.delenv("HIVEMIND_TRUSTED_PROXY_CIDRS", raising=False)
    proto = _make_proto()
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_headers"] == (
        "x-hivemind-client-ip",
        "x-forwarded-for",
        "x-real-ip",
    )


def test_config_headers_override_default():
    proto = _make_proto({"trusted_client_ip_headers": "x-custom-ip"})
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_headers"] == ("x-custom-ip",)


def test_env_headers_used_when_config_absent(monkeypatch):
    monkeypatch.setenv("HIVEMIND_TRUSTED_CLIENT_IP_HEADERS", "x-real-ip")
    proto = _make_proto()
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_headers"] == ("x-real-ip",)


def test_explicit_empty_headers_disables_feature(monkeypatch):
    monkeypatch.setenv("HIVEMIND_TRUSTED_CLIENT_IP_HEADERS", "x-from-env")
    proto = _make_proto({"trusted_client_ip_headers": []})
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_headers"] == ()


def test_headers_are_lowercased():
    proto = _make_proto({"trusted_client_ip_headers": "X-Forwarded-For,X-Real-IP"})
    settings = _run_until_settings_loaded(proto)
    assert settings["trusted_headers"] == ("x-forwarded-for", "x-real-ip")


def test_invalid_cidrs_are_skipped_not_raised():
    proto = _make_proto({
        "trusted_proxy_cidrs": "10.0.0.0/8,not-a-cidr,192.168.0.0/16",
    })
    settings = _run_until_settings_loaded(proto)
    assert len(settings["trusted_networks"]) == 2
