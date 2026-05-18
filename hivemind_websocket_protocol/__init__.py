import asyncio
import binascii
import dataclasses
import ipaddress
import os
import os.path
import random
from os import makedirs
from os.path import exists, join
from socket import gethostname
from typing import Dict, Any, Optional, Tuple
from urllib.parse import unquote

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

    @staticmethod
    def _config_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, (list, tuple, set)):
            items = [str(item).strip() for item in value]
            return [item for item in items if item]
        item = str(value).strip()
        return [item] if item else []

    @classmethod
    def _trusted_proxy_networks(cls, value: Any) -> tuple[Any, ...]:
        networks = []
        for proxy_cidr in cls._config_list(value):
            try:
                networks.append(ipaddress.ip_network(proxy_cidr, strict=False))
            except ValueError:
                LOG.warning(f"Ignoring invalid trusted proxy CIDR: {proxy_cidr}")
        return tuple(networks)

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
                or "x-hivemind-client-ip"
            )
        HiveMindTornadoWebSocket.trusted_proxy_networks = self._trusted_proxy_networks(
            proxy_cidrs
        )
        HiveMindTornadoWebSocket.trusted_client_ip_headers = tuple(
            header.lower() for header in self._config_list(client_ip_headers)
        )

        ssl = self.config.get("ssl", False)
        cert_dir: str = self.config.get("cert_dir") or f"{xdg_data_home()}/hivemind"
        cert_name: str = self.config.get("cert_name") or "hivemind"
        host = self.config.get("host") or self.identity.default_master or "0.0.0.0"
        host = host.split("://")[-1]
        port = int(self.config.get("port") or self.identity.default_port or 5678)

        routes: list = [("/", HiveMindTornadoWebSocket)]
        application = web.Application(routes)
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
            # TODO: Don't use SHA1
            cert.sign(k, "sha1")

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
    trusted_client_ip_headers: tuple[str, ...] = ("x-hivemind-client-ip",)
    trusted_proxy_networks: tuple[Any, ...] = ()

    @staticmethod
    def _normalize_ip(value: str | None) -> Optional[str]:
        if not isinstance(value, str):
            return None
        candidate = value.strip().strip('"')
        if not candidate:
            return None
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        elif candidate.count(":") == 1 and "." in candidate:
            candidate = candidate.rsplit(":", 1)[0]
        candidate = candidate.split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None

    def _header_ip_candidates(self) -> list[list[str]]:
        candidate_groups: list[list[str]] = []
        seen: set[str] = set()
        for header in self.trusted_client_ip_headers:
            header_value = self.request.headers.get(header)
            if not isinstance(header_value, str):
                continue
            if header == "x-forwarded-for":
                values = header_value.split(",")
            elif header == "forwarded":
                values = []
                for entry in header_value.split(","):
                    for token in entry.split(";"):
                        key, separator, value = token.strip().partition("=")
                        if separator and key.lower() == "for":
                            values.append(value)
            else:
                values = [header_value]

            candidates: list[str] = []
            for value in values:
                ip_value = self._normalize_ip(value)
                if ip_value and ip_value not in seen:
                    candidates.append(ip_value)
                    seen.add(ip_value)

            if candidates:
                candidate_groups.append(candidates)

        return candidate_groups

    @staticmethod
    def _is_global_ip(value: str | None) -> bool:
        if not value:
            return False
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False

    def _connection_ip(self) -> Optional[str]:
        remote_ip = self._normalize_ip(getattr(self.request, "remote_ip", None))
        if self._is_trusted_proxy(remote_ip):
            for candidates in self._header_ip_candidates():
                return self._client_ip_from_candidates(candidates)
        if self._is_global_ip(remote_ip):
            return remote_ip
        return remote_ip

    def _client_ip_from_candidates(self, candidates: list[str]) -> str:
        for candidate in reversed(candidates):
            if not self._is_trusted_proxy(candidate):
                return candidate
        return candidates[0]

    @classmethod
    def _is_trusted_proxy(cls, remote_ip: str | None) -> bool:
        if not remote_ip or not cls.trusted_proxy_networks:
            return False
        try:
            ip_address = ipaddress.ip_address(remote_ip)
        except ValueError:
            return False
        return any(ip_address in network for network in cls.trusted_proxy_networks)


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
            userpass_encoded = bytes(auth.strip(), encoding="utf-8")
            userpass_decoded = pybase64.b64decode(userpass_encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("invalid authorization encoding") from e
        if ":" not in userpass_decoded:
            raise ValueError("invalid authorization payload")
        name, key = userpass_decoded.split(":", 1)
        if not name or not key:
            raise ValueError("invalid authorization payload")
        return name, key

    @staticmethod
    def _query_argument(query: str | bytes | None, name: str) -> Optional[str]:
        if isinstance(query, bytes):
            query = query.decode("utf-8", errors="ignore")
        if not isinstance(query, str) or not query:
            return None
        for part in query.split("&"):
            key, separator, value = part.partition("=")
            if unquote(key) == name:
                return unquote(value) if separator else ""
        return None

    def on_message(self, message: str) -> None:
        """
        Handle incoming messages from the WebSocket.

        Args:
            message (str): The incoming message.
        """
        message = self.client.decode(message)
        source_ip = getattr(self.client, "source_ip", None)
        source_label = f" from {source_ip}" if source_ip else ""
        if (
                message.msg_type == HiveMessageType.BUS
                and message.payload.msg_type == "recognizer_loop:b64_audio"
        ):
            LOG.info(f"Received {self.client.peer}{source_label} sent base64 audio for STT")
        else:
            LOG.info(f"Received {self.client.peer}{source_label} message: {message}")
        self.hm_protocol.handle_message(message, self.client)

    def open(self) -> None:
        """
        Handle a new client connection and perform authorization.
        """
        source_ip = self._connection_ip()
        auth = self._query_argument(getattr(self.request, "query", None), "authorization")
        try:
            useragent, key = self.decode_auth(auth)
        except ValueError as e:
            LOG.warning(f"Rejecting websocket connection from {source_ip or 'unknown'}: {e}")
            self.close(code=1008, reason=str(e))
            return
        LOG.info(f"Authorizing client from {source_ip or 'unknown'} - {useragent}")

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
        self.client.source_ip = source_ip
        self.hm_protocol.db.sync()
        user: Client = self.hm_protocol.db.get_client_by_api_key(key)

        if not user:
            LOG.error("Client provided an invalid api key")
            self.hm_protocol.handle_invalid_key_connected(self.client)
            self.close()
            return

        self.client.name = f"{useragent}::{user.client_id}::{user.name}"
        self.client.crypto_key = user.crypto_key
        self.client.msg_blacklist = user.message_blacklist or []
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
            LOG.debug("disconnecting unauthenticated websocket client")
            return
        source_ip = getattr(client, "source_ip", None)
        source_label = f" from {source_ip}" if source_ip else ""
        LOG.info(f"disconnecting client: {client.peer}{source_label}")
        self.hm_protocol.handle_client_disconnected(client)

    def check_origin(self, origin) -> bool:
        return True
