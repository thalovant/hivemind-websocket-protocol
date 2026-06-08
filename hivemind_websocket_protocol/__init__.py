import asyncio
import binascii
import dataclasses
import math
import os
import os.path
import random
from os import makedirs
from os.path import exists, join
from socket import gethostname
from typing import Dict, Any, Optional, Tuple

import pybase64
from OpenSSL import crypto
from hivemind_plugin_manager.protocols import NetworkProtocol
from ovos_bus_client.session import Session
from ovos_utils.log import LOG
from ovos_utils.xdg_utils import xdg_data_home
from poorman_handshake import PasswordHandShake
from tornado import ioloop
from tornado import web
from tornado.platform.asyncio import AnyThreadEventLoopPolicy
from tornado.websocket import WebSocketHandler

from hivemind_bus_client.message import HiveMessageType
from hivemind_core.protocol import (
    HiveMindListenerProtocol,
    HiveMindClientConnection,
    HiveMindNodeType
)
from hivemind_plugin_manager.protocols import ClientCallbacks
from hivemind_plugin_manager.database import Client

from hivemind_websocket_protocol._client_ip import (
    parse_networks,
    resolve_client_ip,
)


DEFAULT_TRUSTED_HEADERS = "x-hivemind-client-ip,x-forwarded-for,x-real-ip"
DEFAULT_WEBSOCKET_PING_INTERVAL = 30.0
DEFAULT_WEBSOCKET_PING_TIMEOUT = 20.0


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

    def run(self):
        LOG.debug(f"websocket server config: {self.config}")
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        HiveMindTornadoWebSocket.loop = ioloop.IOLoop.current()
        HiveMindTornadoWebSocket.hm_protocol = self.hm_protocol

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
        if ssl:
            cert_file = f"{cert_dir}/{cert_name}.crt"
            key_file = f"{cert_dir}/{cert_name}.key"
            if not os.path.isfile(key_file):
                LOG.info("generating self-signed SSL certificate")
                cert_file, key_file = self.create_self_signed_cert(cert_dir, cert_name)
            LOG.debug("using ssl key at " + key_file)
            LOG.debug("using ssl certificate at " + cert_file)
            ssl_options = {"certfile": cert_file, "keyfile": key_file}

            LOG.info("wss listener started")
            application.listen(port, host, ssl_options=ssl_options)
        else:
            LOG.info("ws listener started")
            application.listen(port, host)

        HiveMindTornadoWebSocket.loop.start()  # blocking

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
    source_ip: Optional[str] = None

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

    def on_message(self, message: str) -> None:
        message = self.client.decode(message)
        if message.msg_type == HiveMessageType.HELLO:
            self._remember_hello_session(message)
        message = self._hydrate_bus_session(message)
        peer = self._peer_label(self.client.peer)
        if (
                message.msg_type == HiveMessageType.BUS
                and message.payload.msg_type == "recognizer_loop:b64_audio"
        ):
            LOG.info(f"Received {peer} sent base64 audio for STT")
        else:
            LOG.info(f"Received {peer} message: {message}")
        self.hm_protocol.handle_message(message, self.client)

    def _peer_label(self, peer: str) -> str:
        return f"{peer} ({self.source_ip})" if self.source_ip else peer

    def open(self) -> None:
        """
        Handle a new client connection and perform authorization.
        """
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
        LOG.info(f"Authorizing client from {self.source_ip or 'unknown'} - {useragent}")

        def do_send(payload: str, is_bin: bool):
            self.loop.install()  # TODO is this needed?
            self.write_message(payload, is_bin)

        def do_disconnect():
            self.loop.install()  # TODO is this needed?
            self.close()

        self.client = HiveMindClientConnection(
            key=key,
            disconnect=do_disconnect,
            send_msg=do_send,
            sess=Session(session_id="default"),  # will be re-assigned once client sends handshake
            name=useragent,
            hm_protocol=self.hm_protocol
        )
        self.client.source_ip = self.source_ip
        self.hm_protocol.db.sync()
        user: Client = self.hm_protocol.db.get_client_by_api_key(key)

        if not user:
            LOG.error("Client provided an invalid api key")
            self.hm_protocol.handle_invalid_key_connected(self.client)
            self.close()
            return

        self.client.name = f"{useragent}::{user.client_id}::{user.name}"
        self.client.crypto_key = user.crypto_key
        self.client.msg_blacklist = getattr(user, "message_blacklist", None) or []
        self.client.skill_blacklist = user.skill_blacklist or []
        self.client.intent_blacklist = user.intent_blacklist or []
        self.client.allowed_types = user.allowed_types
        self.client.can_broadcast = user.can_broadcast
        self.client.can_propagate = user.can_propagate
        self.client.can_escalate = user.can_escalate
        self.client.is_admin = user.is_admin
        if user.password:
            # pre-shared password to derive aes_key
            self.client.pswd_handshake = PasswordHandShake(user.password)

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

        self.hm_protocol.handle_new_client(self.client)
        # self.write_message(Message("connected").serialize())

    def on_close(self):
        client = getattr(self, "client", None)
        if client is None:
            LOG.debug(
                f"closing unauthenticated websocket from {self.request.remote_ip} "
                f"(no client was ever attached)"
            )
            return
        LOG.info(f"disconnecting client: {self._peer_label(client.peer)}")
        self.hm_protocol.handle_client_disconnected(client)

    def check_origin(self, origin) -> bool:
        return True
