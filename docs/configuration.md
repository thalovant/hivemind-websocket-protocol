# Configuration Reference

Configuration is passed as a dict in the `hivemind-websocket-plugin` block of
`~/.config/hivemind-core/server.json`. Dict keys always take precedence over
environment variables.

## Connection

| Key | Type | Default | Description |
|---|---|---|---|
| `host` | `str` | `0.0.0.0` | Bind address. Falls back to `identity.default_master`. |
| `port` | `int` | `5678` | Listen port. Falls back to `identity.default_port`. |
| `ssl` | `bool` | `false` | Enable TLS (`wss://`). |
| `cert_dir` | `str` | `$XDG_DATA_HOME/hivemind` | Directory for TLS cert/key files. |
| `cert_name` | `str` | `hivemind` | Base filename; produces `<name>.crt` and `<name>.key`. |

When `ssl=true` and the key file does not exist, a self-signed 2048-bit RSA
certificate valid for 10 years is generated automatically.

## Trusted-proxy IP resolution

| Key | Env var | Default | Description |
|---|---|---|---|
| `trusted_proxy_cidrs` | `HIVEMIND_TRUSTED_PROXY_CIDRS` | _(none — feature disabled)_ | Comma-separated CIDRs of trusted proxy addresses. |
| `trusted_client_ip_headers` | `HIVEMIND_TRUSTED_CLIENT_IP_HEADERS` | `x-hivemind-client-ip,x-forwarded-for,x-real-ip` | Ordered list of headers to inspect for the real client IP. |

Both keys accept a `str`, `list`, or `tuple`. Env vars accept comma-separated
strings. The feature is **inactive** unless at least one CIDR is configured.

When inactive, `remote_ip` from the Tornado request is used as-is.

## WebSocket heartbeat

| Key | Env var | Default | Description |
|---|---|---|---|
| `websocket_ping_interval` | `HIVEMIND_WEBSOCKET_PING_INTERVAL` | `30.0` | Seconds between WebSocket ping frames. |
| `websocket_ping_timeout` | `HIVEMIND_WEBSOCKET_PING_TIMEOUT` | `20.0` | Seconds to wait for pong before closing the connection. |
| `auth_executor_workers` | `HIVEMIND_WEBSOCKET_AUTH_EXECUTOR_WORKERS` | `64` | Workers for remote authorization and admission callbacks. |
| `auth_queue_size` | `HIVEMIND_WEBSOCKET_AUTH_QUEUE_SIZE` | `64` | Additional authorization requests allowed to wait; excess sockets close with status `1013`. |
| `handshake_executor_workers` | `HIVEMIND_WEBSOCKET_HANDSHAKE_EXECUTOR_WORKERS` | `32` | Workers for password and protocol handshake work. |
| `disconnect_executor_workers` | `HIVEMIND_WEBSOCKET_DISCONNECT_EXECUTOR_WORKERS` | `1` | Ordered workers for disconnect lifecycle callbacks; keep at `1` unless the callback chain is proven thread-safe. |
| `prefer_preshared_key` | `HIVEMIND_WEBSOCKET_PREFER_PRESHARED_KEY` | `true` | When both credentials exist, prefer the high-entropy pre-shared crypto key and skip redundant password-strength analysis while retaining the compatibility handshake advertisement. Clients without a crypto key still receive full password validation. Set `false` only for a legacy client that explicitly requires password validation at listener admission. |
| `slow_admission_log_ms` | `HIVEMIND_WEBSOCKET_SLOW_ADMISSION_LOG_MS` | `500` | Emit credential-free stage timings when WebSocket application admission exceeds this threshold. Set `0` to trace every admission. |

Invalid, negative, non-finite, or non-positive values fall back to the
applicable defaults.

### Example — nginx on localhost

```bash
export HIVEMIND_TRUSTED_PROXY_CIDRS="127.0.0.1/32"
export HIVEMIND_TRUSTED_CLIENT_IP_HEADERS="x-forwarded-for"
```

### Example — private network proxies via config

```json
{
  "network_protocol": {
    "module": "hivemind-websocket-plugin",
    "hivemind-websocket-plugin": {
      "trusted_proxy_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
      "trusted_client_ip_headers": ["x-forwarded-for", "x-real-ip"]
    }
  }
}
```

See [architecture.md](architecture.md#ip-resolution-flow) for the full algorithm.

## Full example

```json
{
  "network_protocol": {
    "module": "hivemind-websocket-plugin",
    "hivemind-websocket-plugin": {
      "host": "0.0.0.0",
      "port": 5678,
      "ssl": true,
      "cert_dir": "/etc/hivemind/ssl",
      "cert_name": "hivemind",
      "trusted_proxy_cidrs": ["127.0.0.1/32"],
      "trusted_client_ip_headers": ["x-forwarded-for"]
    }
  }
}
```
