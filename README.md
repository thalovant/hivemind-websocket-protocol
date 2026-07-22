# hivemind-websocket-protocol

WebSocket transport plugin for [hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core).

This is the **reference network protocol** for HiveMind. Satellites and clients connect to the hub
over a persistent WebSocket connection (`ws://` or `wss://`). All HiveMessage frames are exchanged
over this connection after an initial authentication handshake.

## Where it fits

```
hivemind-core
  └── hivemind-plugin-manager  (NetworkProtocolFactory loads plugins by entry-point)
        └── hivemind-websocket-protocol  ← this repo
              └── Tornado WebSocket server
```

The plugin registers under the `hivemind.network.protocol` entry-point group as
`hivemind-websocket-plugin`. `hivemind-core` loads it automatically when `server.json`
sets `network_protocol.module` to this name. It is the default transport and is loaded
without any explicit config when none is provided.

## Install

```bash
pip install hivemind-websocket-protocol
```

## Quickstart

The default transport requires no explicit configuration. To confirm it is active or to
customize it, add the following to `~/.config/hivemind-core/server.json`:

```json
{
  "network_protocol": {
    "module": "hivemind-websocket-plugin",
    "hivemind-websocket-plugin": {
      "host": "0.0.0.0",
      "port": 5678
    }
  }
}
```

Start hivemind-core:

```bash
hivemind-core listen
```

Clients connect to `ws://<host>:5678/?authorization=<base64(name:key)>`.

### Enable TLS (wss://)

```json
{
  "network_protocol": {
    "module": "hivemind-websocket-plugin",
    "hivemind-websocket-plugin": {
      "host": "0.0.0.0",
      "port": 5678,
      "ssl": true,
      "cert_dir": "/etc/hivemind/ssl",
      "cert_name": "hivemind"
    }
  }
}
```

If the key file does not exist at `<cert_dir>/<cert_name>.key`, a self-signed 2048-bit
RSA certificate valid for 10 years is generated automatically. For production, replace
the auto-generated cert with a properly signed one.

### Behind a reverse proxy

When hivemind-core runs behind nginx or another reverse proxy, configure trusted CIDRs
so the plugin reads the real client IP from the forwarded header:

```json
{
  "network_protocol": {
    "module": "hivemind-websocket-plugin",
    "hivemind-websocket-plugin": {
      "trusted_proxy_cidrs": ["127.0.0.1/32"],
      "trusted_client_ip_headers": ["x-forwarded-for"]
    }
  }
}
```

Or via environment variables:

```bash
export HIVEMIND_TRUSTED_PROXY_CIDRS="127.0.0.1/32"
export HIVEMIND_TRUSTED_CLIENT_IP_HEADERS="x-forwarded-for"
```

## Configuration reference

| Key | Env var | Default | Description |
|---|---|---|---|
| `host` | — | `0.0.0.0` | Bind address. Falls back to `identity.default_master`. |
| `port` | — | `5678` | Listen port. Falls back to `identity.default_port`. |
| `ssl` | — | `false` | Enable TLS. |
| `cert_dir` | — | `$XDG_DATA_HOME/hivemind` | Directory for TLS cert and key files. |
| `cert_name` | — | `hivemind` | Base filename; produces `<name>.crt` and `<name>.key`. |
| `trusted_proxy_cidrs` | `HIVEMIND_TRUSTED_PROXY_CIDRS` | _(none)_ | Comma-separated CIDRs of trusted proxy addresses. |
| `trusted_client_ip_headers` | `HIVEMIND_TRUSTED_CLIENT_IP_HEADERS` | `x-hivemind-client-ip,x-forwarded-for,x-real-ip` | Ordered list of headers to inspect for real client IP. |
| `websocket_ping_interval` | `HIVEMIND_WEBSOCKET_PING_INTERVAL` | `30.0` | Seconds between WebSocket ping frames. |
| `websocket_ping_timeout` | `HIVEMIND_WEBSOCKET_PING_TIMEOUT` | `20.0` | Seconds to wait for pong before closing the connection. |
| `prefer_preshared_key` | `HIVEMIND_WEBSOCKET_PREFER_PRESHARED_KEY` | `false` | When both credentials exist, prefer the high-entropy pre-shared crypto key and skip redundant password-strength analysis while retaining the compatibility handshake advertisement. |

Both `trusted_proxy_cidrs` and `trusted_client_ip_headers` accept a string, list, or
tuple. The feature is disabled unless at least one CIDR is configured.

## Docs

- [docs/architecture.md](docs/architecture.md) — handler lifecycle, authorization flow, IP resolution
- [docs/configuration.md](docs/configuration.md) — full configuration reference
- [docs/operations.md](docs/operations.md) — TLS, reverse proxy, authoring a transport plugin
