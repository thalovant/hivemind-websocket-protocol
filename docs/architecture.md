# Architecture

## Class hierarchy

```
hivemind_plugin_manager.protocols.NetworkProtocol  (abstract)
        │
        └─ hivemind_websocket_protocol.HiveMindWebsocketProtocol
                │
                └─ HiveMindTornadoWebSocket  (per-connection handler)
```

`HiveMindWebsocketProtocol.run()` is the blocking server entry point called by
`hivemind-core`. It builds a Tornado `Application`, optionally wraps it in TLS,
and starts the `IOLoop`.

`HiveMindTornadoWebSocket` extends `tornado.websocket.WebSocketHandler` and
manages one WebSocket connection per instance.

## Handler lifecycle

### `open()`

1. Resolve the real client IP via `_client_ip()` (see [IP resolution](#ip-resolution-flow)).
2. Read the `?authorization=` query parameter from the URL.
3. Decode it with `decode_auth()` — Base64, format `name:key`. Reject with
   close code `1008` if decoding fails or credentials are empty.
4. Look up the API key in `hm_protocol.db`. Close if not found.
5. Populate `HiveMindClientConnection` with permissions from the database record
   (`allowed_types`, `can_broadcast`, `can_escalate`, `can_propagate`, `is_admin`,
   `crypto_key`, `pswd_handshake` if a password is set).
6. Check crypto requirements: if `require_crypto` is enabled and no pre-shared key
   or handshake is available, reject.
7. Call `hm_protocol.handle_new_client(client)`.

### `on_message()`

Decodes the raw WebSocket frame via `client.decode()`, then dispatches to
`hm_protocol.handle_message(message, client)`. Binary audio frames
(`recognizer_loop:b64_audio` inside a `BUS` message) are logged separately.

### `on_close()`

Guards against connections that never completed `open()` (where `self.client`
was never set), then calls `hm_protocol.handle_client_disconnected(client)`.

## Authorization

Clients connect with a URL query parameter:

```
ws://host:port/?authorization=<base64(name:key)>
```

`decode_auth()` decodes the Base64 value and splits on the first `:`. Both
`name` and `key` must be non-empty; otherwise the connection is rejected with
close code `1008`.

The `name` component is the client's display name (user agent). The `key`
component is the API key that `hivemind-core` provisioned via `add-client`.

## IP resolution flow

When hivemind-core runs behind a reverse proxy, the connection's `remote_ip`
is the proxy address, not the satellite's real IP. The plugin resolves the
real IP as follows:

1. If `trusted_proxy_cidrs` is not configured, return `remote_ip` unchanged.
2. If `remote_ip` is not in any trusted CIDR, return `remote_ip` unchanged
   (not a proxy hop we trust).
3. Iterate `trusted_client_ip_headers` left-to-right. For each header present,
   split on commas and walk the addresses **right-to-left** (rightmost hop is
   the closest, most-trusted proxy in the chain).
4. Return the first address that is not in `trusted_networks`.
5. Fall back to `remote_ip` if all candidates are trusted or headers are absent.

IPv4 and IPv6 are both handled. Tokens that are not valid IP addresses
(e.g. `unknown`, port-suffixed values like `10.0.0.1:1234`) are silently
skipped per RFC 7239 intent.

`parse_networks()` uses `strict=False` so host bits in a CIDR are silently
masked (e.g. `192.168.1.5/24` is treated as `192.168.1.0/24`).

## TLS

When `ssl=true`, the plugin wraps the Tornado listener with
`ssl_options={"certfile": ..., "keyfile": ...}`. If the key file does not
exist, `create_self_signed_cert()` generates a 2048-bit RSA self-signed
certificate valid for 10 years. The certificate is written to
`<cert_dir>/<cert_name>.crt` and the key to `<cert_dir>/<cert_name>.key`.

For production, replace the auto-generated files with a properly signed
certificate. The plugin reads the files on startup and uses whatever is there;
it does not hot-reload on file change.

## Authoring a transport plugin

Implement `NetworkProtocol` from `hivemind_plugin_manager.protocols`:

```python
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from hivemind_plugin_manager.protocols import NetworkProtocol, ClientCallbacks
from hivemind_core.protocol import HiveMindListenerProtocol

@dataclass
class MyProtocol(NetworkProtocol):
    config: Dict[str, Any] = field(default_factory=dict)
    hm_protocol: Optional[HiveMindListenerProtocol] = None
    callbacks: ClientCallbacks = field(default_factory=ClientCallbacks)

    def run(self):
        # blocking server loop
        ...
```

Register it under `hivemind.network.protocol` in `pyproject.toml`:

```toml
[project.entry-points."hivemind.network.protocol"]
"my-transport-plugin" = "my_package:MyProtocol"
```

`NetworkProtocolFactory.create("my-transport-plugin")` will discover and
instantiate it.
