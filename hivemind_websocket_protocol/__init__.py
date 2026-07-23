import asyncio
import binascii
import copy
import dataclasses
import hashlib
import math
import os
import os.path
import random
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from os import makedirs
from os.path import exists, join
from threading import Lock
from socket import gethostname
from typing import Dict, Any, Optional, Tuple

import pybase64
from OpenSSL import crypto
from hivemind_plugin_manager.protocols import NetworkProtocol
from ovos_bus_client.session import Session
from ovos_utils.log import LOG
from ovos_utils.xdg_utils import xdg_data_home
from poorman_handshake import HandShake, PasswordHandShake, check_password_strength
from tornado import ioloop
from tornado import web
from tornado.iostream import StreamClosedError
from tornado.websocket import WebSocketClosedError, WebSocketHandler

from hivemind_bus_client.message import HiveMessageType
try:
    from hivemind_core.config import runtime_password_min_bits
except ImportError:  # released hivemind-core without the helper
    def runtime_password_min_bits():
        disabled = os.environ.get(
            "HIVEMIND_DISABLE_PASSWORD_STRENGTH_CHECK",
            "",
        ).strip().lower()
        return 0.0 if disabled in ("1", "true", "yes", "on") else 40.0

from hivemind_core.protocol import (
    HiveMindListenerProtocol,
    HiveMindClientConnection,
    HiveMindNodeType
)
from hivemind_plugin_manager.protocols import ClientCallbacks
from hivemind_plugin_manager.database import AbstractRemoteDB, Client

from hivemind_websocket_protocol._client_ip import (
    parse_networks,
    resolve_client_ip,
)


DEFAULT_TRUSTED_HEADERS = "x-hivemind-client-ip,x-forwarded-for,x-real-ip"
DEFAULT_WEBSOCKET_PING_INTERVAL = 30.0
DEFAULT_WEBSOCKET_PING_TIMEOUT = 20.0
DEFAULT_AUTH_EXECUTOR_WORKERS = 64
DEFAULT_HANDSHAKE_EXECUTOR_WORKERS = 32
DEFAULT_PREFER_PRESHARED_KEY = True
DEFAULT_DISCONNECT_EXECUTOR_WORKERS = 1
DEFAULT_CONNECT_LIFECYCLE_EXECUTOR_WORKERS = 16
DEFAULT_SLOW_ADMISSION_LOG_MS = 500.0


_HANDSHAKE_TEMPLATE_CACHE: Dict[
    str,
    Tuple[Tuple[str, int, int, int, int], HandShake],
] = {}
_HANDSHAKE_TEMPLATE_LOCK = Lock()
_PASSWORD_STRENGTH_LOCK = Lock()
_PASSWORD_STRENGTH_CACHE: "OrderedDict[Tuple[bytes, float], None]" = OrderedDict()
_PASSWORD_STRENGTH_CACHE_KEY = os.urandom(32)
_PASSWORD_STRENGTH_CACHE_SIZE = 4096


def _private_key_fingerprint(path: Optional[str]) -> Optional[Tuple[str, int, int, int, int]]:
    """Return a cheap rotation-aware fingerprint for a listener private key."""
    if not path or not os.path.isfile(path):
        return None
    resolved = os.path.realpath(path)
    stat = os.stat(resolved)
    return resolved, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _new_client_handshake(path: Optional[str]) -> HandShake:
    """Create isolated handshake state without reparsing an unchanged RSA key."""
    fingerprint = _private_key_fingerprint(path)
    if fingerprint is None:
        return HandShake(path)

    cache_key = os.path.abspath(path)
    with _HANDSHAKE_TEMPLATE_LOCK:
        cached = _HANDSHAKE_TEMPLATE_CACHE.get(cache_key)
        if cached is None or cached[0] != fingerprint:
            template = HandShake(path)
            current_fingerprint = _private_key_fingerprint(path)
            if current_fingerprint is None:
                return template
            _HANDSHAKE_TEMPLATE_CACHE[cache_key] = (current_fingerprint, template)
        else:
            template = cached[1]

        handshake = copy.copy(template)

    # These fields are connection-local and must never leak across copies.
    handshake.target_key = None
    handshake.secret = None
    return handshake


def _new_password_handshake(
    password: str,
    min_bits: Optional[float] = None,
) -> PasswordHandShake:
    """Validate the credential away from Tornado's event loop."""
    if min_bits is None:
        min_bits = runtime_password_min_bits()
    if min_bits > 0:
        # This keyed process-local fingerprint is an LRU lookup key, not a
        # stored password hash. Rotation changes the fingerprint and forces a
        # fresh validation; the random key is never persisted.
        digest = hashlib.blake2s(
            password.encode("utf-8"),
            key=_PASSWORD_STRENGTH_CACHE_KEY,
        ).digest()  # lgtm[py/weak-sensitive-data-hashing]
        cache_key = (digest, min_bits)
        with _PASSWORD_STRENGTH_LOCK:
            if cache_key not in _PASSWORD_STRENGTH_CACHE:
                check_password_strength(password, min_bits=min_bits)
                _PASSWORD_STRENGTH_CACHE[cache_key] = None
                while len(_PASSWORD_STRENGTH_CACHE) > _PASSWORD_STRENGTH_CACHE_SIZE:
                    _PASSWORD_STRENGTH_CACHE.popitem(last=False)
            _PASSWORD_STRENGTH_CACHE.move_to_end(cache_key)
    return PasswordHandShake(password, min_bits=0)


def _refresh_local_client_database(database: Any) -> bool:
    """Reload file-backed clients without repairing a live remote database."""
    backend = getattr(database, "db", database)
    if isinstance(backend, AbstractRemoteDB):
        return False
    sync = getattr(database, "sync", None)
    if not callable(sync):
        return False
    sync()
    return True


def _finish_websocket_write(future: Any) -> None:
    """Consume asynchronous write failures so closed peers stay routine."""
    if future.cancelled():
        return
    error = future.exception()
    if error is None:
        return
    if isinstance(error, (WebSocketClosedError, StreamClosedError)):
        LOG.debug("HiveMind websocket closed before a queued write completed")
        return
    LOG.error(
        "HiveMind websocket write failed: "
        f"{type(error).__name__}: {error!r}"
    )


def _finish_disconnect_callback(future: Any) -> None:
    """Observe deferred disconnect failures without blocking Tornado."""
    if future.cancelled():
        return
    error = future.exception()
    if error is not None:
        LOG.error(
            "HiveMind websocket disconnect callback failed: "
            f"{type(error).__name__}: {error!r}"
        )


def _finish_connect_lifecycle(
        handler: "HiveMindTornadoWebSocket", future: Any) -> None:
    """Observe deferred connect lifecycle failures and close fail-closed."""
    if future.cancelled():
        return
    error = future.exception()
    if error is None:
        return
    LOG.error(
        "HiveMind websocket connect lifecycle failed: "
        f"{type(error).__name__}: {error!r}"
    )
    handler.loop.add_callback(
        handler.close,
        1011,
        "client lifecycle unavailable",
    )


def _write_websocket_message(handler: WebSocketHandler,
                             payload: str,
                             is_binary: bool) -> None:
    """Write a frame and observe both synchronous and future failures."""
    try:
        future = handler.write_message(payload, is_binary)
    except (WebSocketClosedError, StreamClosedError):
        LOG.debug("HiveMind websocket closed before a frame could be queued")
        return
    if future is not None:
        future.add_done_callback(_finish_websocket_write)


def _split_csv(value: Any) -> Tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return tuple(v.strip() for v in value.split(",") if v.strip())
    return tuple(str(v).strip() for v in value if str(v).strip())


def _non_negative_float(value: Any, default: float, name: str) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        LOG.warning(f"Ignoring invalid {name}: {value!r}")
        return default
    if not math.isfinite(parsed):
        LOG.warning(f"Ignoring invalid {name}: {value!r}")
        return default
    if parsed < 0:
        LOG.warning(f"Ignoring negative {name}: {value!r}")
        return default
    return parsed


def _positive_int(value: Any, default: int, name: str) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        LOG.warning(f"Ignoring invalid {name}: {value!r}")
        return default
    if parsed < 1:
        LOG.warning(f"Ignoring non-positive {name}: {value!r}")
        return default
    return parsed


def _boolean(value: Any, default: bool, name: str) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    LOG.warning(f"Ignoring invalid {name}: {value!r}")
    return default


@dataclasses.dataclass
class HiveMindWebsocketProtocol(NetworkProtocol):
    """
    WebSocket handler for managing HiveMind client connections.

    Attributes:
        hm_protocol (Optional[HiveMindListenerProtocol]): The protocol instance for handling HiveMind messages.
    """
    config: Dict[str, Any] = dataclasses.field(default_factory=dict)
    hm_protocol: Optional[HiveMindListenerProtocol] = None
    callbacks: ClientCallbacks = dataclasses.field(default_factory=ClientCallbacks)

    def _websocket_ping_settings(self) -> Dict[str, float]:
        interval = self.config.get(
            "websocket_ping_interval",
            os.getenv("HIVEMIND_WEBSOCKET_PING_INTERVAL"),
        )
        timeout = self.config.get(
            "websocket_ping_timeout",
            os.getenv("HIVEMIND_WEBSOCKET_PING_TIMEOUT"),
        )
        return {
            "websocket_ping_interval": _non_negative_float(
                interval,
                DEFAULT_WEBSOCKET_PING_INTERVAL,
                "websocket_ping_interval",
            ),
            "websocket_ping_timeout": _non_negative_float(
                timeout,
                DEFAULT_WEBSOCKET_PING_TIMEOUT,
                "websocket_ping_timeout",
            ),
        }

    def _prefer_preshared_key(self) -> bool:
        return _boolean(
            self.config.get(
                "prefer_preshared_key",
                os.getenv("HIVEMIND_WEBSOCKET_PREFER_PRESHARED_KEY"),
            ),
            DEFAULT_PREFER_PRESHARED_KEY,
            "prefer_preshared_key",
        )

    def _slow_admission_log_ms(self) -> float:
        return _non_negative_float(
            self.config.get(
                "slow_admission_log_ms",
                os.getenv("HIVEMIND_WEBSOCKET_SLOW_ADMISSION_LOG_MS"),
            ),
            DEFAULT_SLOW_ADMISSION_LOG_MS,
            "slow_admission_log_ms",
        )

    def run(self):
        LOG.debug(f"websocket server config: {self.config}")
        asyncio_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(asyncio_loop)
        loop = ioloop.IOLoop.current()
        password_min_bits = runtime_password_min_bits()
        auth_executor = ThreadPoolExecutor(
            max_workers=_positive_int(
                self.config.get(
                    "auth_executor_workers",
                    os.getenv("HIVEMIND_WEBSOCKET_AUTH_EXECUTOR_WORKERS"),
                ),
                DEFAULT_AUTH_EXECUTOR_WORKERS,
                "auth_executor_workers",
            ),
            thread_name_prefix="hivemind-wss-auth",
        )
        handshake_executor = ThreadPoolExecutor(
            max_workers=_positive_int(
                self.config.get(
                    "handshake_executor_workers",
                    os.getenv("HIVEMIND_WEBSOCKET_HANDSHAKE_EXECUTOR_WORKERS"),
                ),
                DEFAULT_HANDSHAKE_EXECUTOR_WORKERS,
                "handshake_executor_workers",
            ),
            thread_name_prefix="hivemind-wss-handshake",
        )
        disconnect_executor = ThreadPoolExecutor(
            max_workers=_positive_int(
                self.config.get(
                    "disconnect_executor_workers",
                    os.getenv("HIVEMIND_WEBSOCKET_DISCONNECT_EXECUTOR_WORKERS"),
                ),
                DEFAULT_DISCONNECT_EXECUTOR_WORKERS,
                "disconnect_executor_workers",
            ),
            thread_name_prefix="hivemind-wss-disconnect",
        )
        connect_lifecycle_executor = ThreadPoolExecutor(
            max_workers=_positive_int(
                self.config.get(
                    "connect_lifecycle_executor_workers",
                    os.getenv(
                        "HIVEMIND_WEBSOCKET_CONNECT_LIFECYCLE_EXECUTOR_WORKERS"
                    ),
                ),
                DEFAULT_CONNECT_LIFECYCLE_EXECUTOR_WORKERS,
                "connect_lifecycle_executor_workers",
            ),
            thread_name_prefix="hivemind-wss-connect-lifecycle",
        )
        HiveMindTornadoWebSocket.loop = loop
        HiveMindTornadoWebSocket.hm_protocol = self.hm_protocol
        HiveMindTornadoWebSocket.auth_executor = auth_executor
        HiveMindTornadoWebSocket.handshake_executor = handshake_executor
        HiveMindTornadoWebSocket.disconnect_executor = disconnect_executor
        HiveMindTornadoWebSocket.connect_lifecycle_executor = (
            connect_lifecycle_executor
        )
        HiveMindTornadoWebSocket.password_min_bits = password_min_bits
        HiveMindTornadoWebSocket.prefer_preshared_key = (
            self._prefer_preshared_key()
        )
        HiveMindTornadoWebSocket.slow_admission_log_ms = (
            self._slow_admission_log_ms()
        )

        if "trusted_proxy_cidrs" in self.config:
            proxy_cidrs = self.config["trusted_proxy_cidrs"]
        else:
            proxy_cidrs = os.getenv("HIVEMIND_TRUSTED_PROXY_CIDRS")

        if "trusted_client_ip_headers" in self.config:
            client_ip_headers = self.config["trusted_client_ip_headers"]
        else:
            client_ip_headers = (
                os.getenv("HIVEMIND_TRUSTED_CLIENT_IP_HEADERS")
                or DEFAULT_TRUSTED_HEADERS
            )
        trusted_networks = parse_networks(_split_csv(proxy_cidrs))
        trusted_headers = tuple(h.lower() for h in _split_csv(client_ip_headers))

        ssl = self.config.get("ssl", False)
        cert_dir: str = self.config.get("cert_dir") or f"{xdg_data_home()}/hivemind"
        cert_name: str = self.config.get("cert_name") or "hivemind"
        host = self.config.get("host") or self.identity.default_master or "0.0.0.0"
        host = host.split("://")[-1]
        port = int(self.config.get("port") or self.identity.default_port or 5678)

        routes: list = [("/", HiveMindTornadoWebSocket)]
        websocket_ping_settings = self._websocket_ping_settings()
        application = web.Application(
            routes,
            trusted_networks=trusted_networks,
            trusted_headers=trusted_headers,
            **websocket_ping_settings,
        )
        startup_error: Optional[Exception] = None

        def start_listener() -> None:
            nonlocal startup_error
            try:
                if ssl:
                    cert_file = f"{cert_dir}/{cert_name}.crt"
                    key_file = f"{cert_dir}/{cert_name}.key"
                    if not os.path.isfile(key_file):
                        LOG.info("generating self-signed SSL certificate")
                        cert_file, key_file = self.create_self_signed_cert(
                            cert_dir, cert_name
                        )
                    LOG.debug("using ssl key at " + key_file)
                    LOG.debug("using ssl certificate at " + cert_file)
                    ssl_options = {"certfile": cert_file, "keyfile": key_file}

                    application.listen(port, host, ssl_options=ssl_options)
                    LOG.info("wss listener started")
                else:
                    application.listen(port, host)
                    LOG.info("ws listener started")
            except Exception as error:
                startup_error = error
                LOG.exception("failed to start websocket listener")
                loop.stop()

        loop.add_callback(start_listener)
        try:
            loop.start()  # blocking
        finally:
            HiveMindTornadoWebSocket.auth_executor = None
            HiveMindTornadoWebSocket.handshake_executor = None
            HiveMindTornadoWebSocket.disconnect_executor = None
            HiveMindTornadoWebSocket.connect_lifecycle_executor = None
            HiveMindTornadoWebSocket.password_min_bits = None
            HiveMindTornadoWebSocket.slow_admission_log_ms = (
                DEFAULT_SLOW_ADMISSION_LOG_MS
            )
            auth_executor.shutdown(wait=True, cancel_futures=True)
            handshake_executor.shutdown(wait=True, cancel_futures=True)
            connect_lifecycle_executor.shutdown(
                wait=True,
                cancel_futures=True,
            )
            disconnect_executor.shutdown(wait=True, cancel_futures=True)
        if startup_error is not None:
            raise startup_error

    @staticmethod
    def create_self_signed_cert(
            cert_dir: str = f"{xdg_data_home()}/hivemind",
            name: str = "hivemind"
    ) -> Tuple[str, str]:
        """
        Create a self-signed certificate and key pair if they do not already exist.

        Args:
            cert_dir (str): The directory where the certificate and key will be stored.
            name (str): The base name for the certificate and key files.

        Returns:
            Tuple[str, str]: The paths to the created certificate and key files.
        """
        cert_file = name + ".crt"
        key_file = name + ".key"
        cert_path = join(cert_dir, cert_file)
        key_path = join(cert_dir, key_file)
        makedirs(cert_dir, exist_ok=True)

        if not exists(join(cert_dir, cert_file)) or not exists(join(cert_dir, key_file)):
            # create a key pair
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)

            # Create a self-signed certificate
            cert = crypto.X509()
            cert.get_subject().C = "PT"
            cert.get_subject().ST = "Europe"
            cert.get_subject().L = "Mountains"
            cert.get_subject().O = "Jarbas AI"
            cert.get_subject().OU = "Powered by HiveMind"
            cert.get_subject().CN = gethostname()
            cert.set_serial_number(random.randint(0, 2000))
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, "sha256")

            open(cert_path, "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            open(key_path, "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        return cert_path, key_path


class HiveMindTornadoWebSocket(WebSocketHandler):
    """
    WebSocket handler for managing HiveMind client connections.

    Attributes:
        hm_protocol (Optional[HiveMindListenerProtocol]): The protocol instance for handling HiveMind messages.
    """
    hm_protocol = None
    auth_executor: Optional[ThreadPoolExecutor] = None
    handshake_executor: Optional[ThreadPoolExecutor] = None
    disconnect_executor: Optional[ThreadPoolExecutor] = None
    connect_lifecycle_executor: Optional[ThreadPoolExecutor] = None
    password_min_bits: Optional[float] = None
    prefer_preshared_key: bool = DEFAULT_PREFER_PRESHARED_KEY
    slow_admission_log_ms: float = DEFAULT_SLOW_ADMISSION_LOG_MS
    source_ip: Optional[str] = None
    _sync_lock = Lock()
    _last_sync_ts = 0.0
    _last_sync_error: Optional[Exception] = None
    _sync_debounce_s = 1.0
    _connect_lifecycle_future: Optional[Any] = None
    _disconnect_submitted: bool = False

    @staticmethod
    def _serialized_session(session: Any) -> dict[str, Any]:
        if isinstance(session, dict):
            return dict(session)
        if hasattr(session, "serialize"):
            try:
                serialized = session.serialize()
            except Exception:
                LOG.exception("Failed to serialize HiveMind client session")
                return {}
            return dict(serialized) if isinstance(serialized, dict) else {}
        return {}

    def _remember_hello_session(self, message: Any) -> None:
        payload = message.payload if hasattr(message, "payload") else None
        if not isinstance(payload, dict):
            return
        raw_session = payload.get("session")
        if not isinstance(raw_session, dict):
            return
        try:
            self.client.sess = Session.deserialize(raw_session)
        except Exception:
            LOG.exception("Failed to cache HiveMind hello session")

    def _hydrate_bus_session(self, message: Any) -> Any:
        if message.msg_type != HiveMessageType.BUS:
            return message

        payload = message.payload
        context = dict(payload.context or {})
        incoming_session = context.get("session")
        if not isinstance(incoming_session, dict):
            return message

        cached_session = self._serialized_session(getattr(self.client, "sess", None))
        if not cached_session:
            return message

        hydrated_session = dict(cached_session)
        hydrated_session.update(incoming_session)
        context["session"] = hydrated_session
        payload.context = context
        message.payload = payload
        return message

    def _client_ip(self) -> Optional[str]:
        return resolve_client_ip(
            getattr(self.request, "remote_ip", None),
            self.request.headers,
            self.settings.get("trusted_networks", ()),
            self.settings.get("trusted_headers", ()),
        )

    @staticmethod
    def decode_auth(auth: str) -> Tuple[str, str]:
        """
        Decode the base64 encoded authorization string.

        Args:
            auth (str): The base64 encoded authorization string.

        Returns:
            Tuple[str, str]: The decoded username and key.
        """
        if not auth:
            raise ValueError("missing authorization")
        try:
            decoded = pybase64.b64decode(auth.strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("invalid authorization encoding") from e
        if ":" not in decoded:
            raise ValueError("invalid authorization payload")
        name, key = decoded.split(":", 1)
        if not name or not key:
            raise ValueError("invalid authorization payload")
        return name, key

    async def on_message(self, message: str) -> None:
        message = self.client.decode(message)
        if message.msg_type == HiveMessageType.HELLO:
            self._remember_hello_session(message)
        message = self._hydrate_bus_session(message)
        peer = self._peer_label(self.client.peer)
        if (
                message.msg_type == HiveMessageType.BUS
                and message.payload.msg_type == "recognizer_loop:b64_audio"
        ):
            LOG.debug(f"Received {peer} sent base64 audio for STT")
        else:
            LOG.debug(f"Received {peer} message: {message}")
        if message.msg_type == HiveMessageType.HANDSHAKE:
            # Password-key derivation uses PBKDF2 and must not serialize every
            # concurrent connection on Tornado's single event-loop thread.
            await self.loop.run_in_executor(
                self.handshake_executor,
                self.hm_protocol.handle_message,
                message,
                self.client,
            )
        else:
            self.hm_protocol.handle_message(message, self.client)

    def _peer_label(self, peer: str) -> str:
        return f"{peer} ({self.source_ip})" if self.source_ip else peer

    def _request_summary(self) -> str:
        """Keep query-string credentials out of Tornado request logs."""
        return (
            f"{self.request.method} {self.request.path} "
            f"({self.request.remote_ip})"
        )

    @classmethod
    def _sync_client_database(cls, database: Any) -> bool:
        """Debounce local database reloads after an API-key cache miss."""
        backend = getattr(database, "db", database)
        if isinstance(backend, AbstractRemoteDB):
            return False
        if not callable(getattr(database, "sync", None)):
            return False

        with cls._sync_lock:
            now = time.monotonic()
            if now - cls._last_sync_ts < cls._sync_debounce_s:
                if cls._last_sync_error is not None:
                    raise cls._last_sync_error
                return True
            cls._last_sync_ts = now
            try:
                refreshed = _refresh_local_client_database(database)
            except Exception as error:
                cls._last_sync_error = error
                raise
            cls._last_sync_error = None
            return refreshed

    async def _lookup_client_by_api_key(self, key: str) -> Optional[Client]:
        """Keep remote credential I/O off Tornado's single event-loop thread."""
        database = self.hm_protocol.db
        backend = getattr(database, "db", database)
        if isinstance(backend, AbstractRemoteDB):
            return await self.loop.run_in_executor(
                self.auth_executor,
                database.get_client_by_api_key,
                key,
            )
        return database.get_client_by_api_key(key)

    async def open(self) -> None:
        """
        Handle a new client connection and perform authorization.
        """
        admission_started = time.monotonic()
        self.source_ip = self._client_ip()
        auth = self.get_query_argument("authorization", None)
        try:
            useragent, key = self.decode_auth(auth)
        except ValueError as e:
            LOG.warning(
                f"rejecting websocket from {self.source_ip or self.request.remote_ip}: "
                f"bad authorization ({e.__class__.__name__}: {e})"
            )
            self.close(code=1008, reason="invalid authorization")
            return
        LOG.debug(f"Authorizing client from {self.source_ip or 'unknown'} - {useragent}")

        def do_send(payload: str, is_bin: bool):
            self.loop.add_callback(
                _write_websocket_message,
                self,
                payload,
                is_bin,
            )

        def do_disconnect():
            self.loop.add_callback(self.close)

        self.client = HiveMindClientConnection(
            key=key,
            disconnect=do_disconnect,
            send_msg=do_send,
            sess=Session(session_id="default"),  # will be re-assigned once client sends handshake
            name=useragent,
            hm_protocol=self.hm_protocol,
            handshake=_new_client_handshake(self.hm_protocol.identity.private_key),
        )
        self.client.source_ip = self.source_ip
        lookup_started = time.monotonic()
        try:
            user: Optional[Client] = await self._lookup_client_by_api_key(key)
        except Exception:
            LOG.exception("Client database lookup failed during websocket authorization")
            self.close(code=1011, reason="client database unavailable")
            return
        lookup_ms = (time.monotonic() - lookup_started) * 1000
        sync_error = False
        if not user:
            try:
                refreshed = self._sync_client_database(self.hm_protocol.db)
            except Exception:
                sync_error = True
                LOG.exception(
                    "Client database sync failed while retrying API-key lookup"
                )
            else:
                if refreshed:
                    user = self.hm_protocol.db.get_client_by_api_key(key)

        if not user:
            if sync_error:
                LOG.error("Client database unavailable during API-key lookup")
                self.close(code=1011, reason="client database unavailable")
                return
            LOG.error("Client provided an invalid api key")
            self.hm_protocol.handle_invalid_key_connected(self.client)
            self.close()
            return

        self.client.name = f"{useragent}::{user.client_id}::{user.name}"
        self.client.crypto_key = user.crypto_key
        self.client.skill_blacklist = user.skill_blacklist or []
        self.client.intent_blacklist = user.intent_blacklist or []
        self.client.allowed_types = user.allowed_types
        self.client.can_broadcast = user.can_broadcast
        self.client.can_propagate = user.can_propagate
        self.client.can_escalate = user.can_escalate
        self.client.is_admin = user.is_admin
        password_started = time.monotonic()
        if user.password:
            # Keep the password handshake available so the core advertises a
            # protocol ceiling compatible with its configured floor. Managed
            # clients that already have a high-entropy crypto key use that PSK,
            # so their password-strength analysis is redundant and need not
            # serialize an otherwise concurrent admission burst.
            min_bits = (
                0.0
                if self.prefer_preshared_key and self.client.crypto_key
                else self.password_min_bits
            )
            self.client.pswd_handshake = await self.loop.run_in_executor(
                self.handshake_executor,
                _new_password_handshake,
                user.password,
                min_bits,
            )
        password_ms = (time.monotonic() - password_started) * 1000

        self.client.node_type = HiveMindNodeType.NODE  # TODO . placeholder

        if (
                not self.client.crypto_key
                and not self.hm_protocol.handshake_enabled
                and self.hm_protocol.require_crypto
        ):
            LOG.error(
                "No pre-shared crypto key for client and handshake disabled, "
                "but configured to require crypto!"
            )
            # clients requiring handshake support might fail here
            self.hm_protocol.handle_invalid_protocol_version(self.client)
            self.close()
            return

        protocol_started = time.monotonic()
        initialize_protocol = getattr(
            self.hm_protocol,
            "handle_new_client_protocol",
            None,
        )
        publish_lifecycle = getattr(
            self.hm_protocol,
            "handle_client_connected",
            None,
        )
        if (
                callable(initialize_protocol)
                and callable(publish_lifecycle)
                and self.connect_lifecycle_executor is not None
        ):
            try:
                initialized = await self.loop.run_in_executor(
                    self.auth_executor,
                    initialize_protocol,
                    self.client,
                )
            except Exception:
                LOG.exception("Client protocol admission failed")
                self.close(code=1011, reason="client admission unavailable")
                return
            if not initialized:
                return
            try:
                lifecycle = self.connect_lifecycle_executor.submit(
                    publish_lifecycle,
                    self.client,
                )
            except RuntimeError:
                LOG.exception("Client lifecycle executor rejected callback")
                self.close(code=1011, reason="client lifecycle unavailable")
                return
            lifecycle.add_done_callback(
                lambda future: _finish_connect_lifecycle(self, future)
            )
            self._connect_lifecycle_future = lifecycle
        else:
            try:
                # Compatibility with cores that expose one combined admission
                # callback. Keep its synchronous I/O off Tornado's event loop.
                await self.loop.run_in_executor(
                    self.auth_executor,
                    self.hm_protocol.handle_new_client,
                    self.client,
                )
            except Exception:
                LOG.exception("Client admission callback failed")
                self.close(code=1011, reason="client admission unavailable")
                return
        protocol_ms = (time.monotonic() - protocol_started) * 1000
        total_ms = (time.monotonic() - admission_started) * 1000
        if total_ms >= self.slow_admission_log_ms:
            LOG.info(
                "Slow HiveMind websocket admission: "
                f"lookup_ms={lookup_ms:.0f} "
                f"password_ms={password_ms:.0f} "
                f"protocol_ms={protocol_ms:.0f} "
                f"total_ms={total_ms:.0f} "
                f"preshared_key={self.client.crypto_key is not None}"
            )
        # self.write_message(Message("connected").serialize())

    def on_close(self):
        client = getattr(self, "client", None)
        if client is None:
            LOG.debug(
                f"closing unauthenticated websocket from {self.request.remote_ip} "
                f"(no client was ever attached)"
            )
            return
        if self._disconnect_submitted:
            return
        self._disconnect_submitted = True
        LOG.debug(f"disconnecting client: {self._peer_label(client.peer)}")
        lifecycle = self._connect_lifecycle_future
        if lifecycle is not None and not lifecycle.done():
            lifecycle.add_done_callback(
                lambda _future: self.loop.add_callback(
                    self._submit_disconnect_callback,
                    client,
                )
            )
            return
        self._submit_disconnect_callback(client)

    def _submit_disconnect_callback(self, client):
        """Publish disconnect only after this client's connect lifecycle."""
        executor = self.disconnect_executor
        if executor is None:
            # Embedded/test harnesses may install the handler without starting
            # HiveMindWebsocketProtocol.run(), which owns the executor. Retain
            # the historical synchronous behavior for those integrations.
            self.hm_protocol.handle_client_disconnected(client)
            return
        try:
            future = executor.submit(
                self.hm_protocol.handle_client_disconnected,
                client,
            )
        except RuntimeError as error:
            LOG.warning(
                "HiveMind websocket disconnect executor rejected callback: "
                f"{error!r}"
            )
            return
        future.add_done_callback(_finish_disconnect_callback)

    def check_origin(self, origin) -> bool:
        return True
