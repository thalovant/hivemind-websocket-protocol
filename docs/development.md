# Development

## Project layout

```
hivemind_websocket_protocol/
    __init__.py          # HiveMindWebsocketProtocol, HiveMindTornadoWebSocket
    _client_ip.py        # parse_networks(), resolve_client_ip()
    version.py           # VERSION_MAJOR / MINOR / BUILD / ALPHA constants
tests/
    test_client_ip.py    # unit tests for IP resolution logic (~50 cases)
    test_decode_auth.py  # unit tests for Base64 auth decoding
    e2e/                 # end-to-end tests (require a running hivemind-core)
```

## Running tests

```bash
pip install pytest
pytest tests/
```

The unit tests in `test_client_ip.py` and `test_decode_auth.py` have no
network dependencies and run offline. The `e2e/` suite requires a live
`hivemind-core` instance.

## Entry-point

The plugin registers under the `hivemind.network.protocol` group:

```
hivemind-websocket-plugin = hivemind_websocket_protocol:HiveMindWebsocketProtocol
```

`hivemind-core` discovers and instantiates it automatically via
`hivemind-plugin-manager`.
