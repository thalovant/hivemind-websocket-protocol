# hivemind-websocket-protocol

WebSocket transport for HiveMind messages.

## Overview

Provides a Tornado-based WebSocket server that connects `hivemind-core`'s
listener protocol to network clients. Clients authenticate via a Base64
query-parameter and exchange `HiveMessage` frames over the socket.

## Key Classes

| Class | Purpose | Source |
|---|---|---|
| `HiveMindWebsocketProtocol` | `NetworkProtocol` plugin; configures and starts the Tornado server | `hivemind_websocket_protocol/__init__.py:50` |
| `HiveMindTornadoWebSocket` | Tornado `WebSocketHandler`; auth, message dispatch, IP resolution | `hivemind_websocket_protocol/__init__.py:161` |
| `resolve_client_ip()` | Resolves real client IP from forwarded headers when peer is a trusted proxy | `hivemind_websocket_protocol/_client_ip.py:28` |
| `parse_networks()` | Parses CIDR strings into `ipaddress` network objects | `hivemind_websocket_protocol/_client_ip.py:10` |

## Contents

- [Installation & Quick Start](../README.md)
- [Architecture](architecture.md)
- [Configuration Reference](configuration.md)
- [Development](development.md)
