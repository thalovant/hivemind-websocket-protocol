# HiveMind Websockets protocol

Transport HiveMessages via websockets

This is the reference implementation of HiveMind, but you can theoretically replace websockets with anything

## Trusted client IPs

When the listener runs behind a proxy, it can log the real client IP from
trusted headers (comma-separated if multiple):

```shell
HIVEMIND_TRUSTED_PROXY_CIDRS=10.42.0.0/16,104.16.0.0/13
HIVEMIND_TRUSTED_CLIENT_IP_HEADERS=x-forwarded-for,x-real-ip
```

When not configured, the listener uses the direct connection's remote IP address
without inspecting any forwarding headers.

These headers are only consulted when the direct connection comes from a trusted
proxy CIDR. For forwarded chains, the listener walks from right to left and uses
the first address that is not in the trusted proxy ranges.
