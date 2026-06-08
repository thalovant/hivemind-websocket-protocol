# Operations

## TLS setup

### Auto-generated self-signed cert (development / internal use)

Set `ssl: true` in config. On the first start, the plugin generates
`<cert_dir>/hivemind.crt` and `<cert_dir>/hivemind.key` automatically.
Clients that connect with `wss://` need to trust the self-signed CA
(or disable verification in test scenarios).

Default cert location: `~/.local/share/hivemind/hivemind.crt`

### Production certificate (Let's Encrypt or your CA)

Place your cert and key at the configured `cert_dir` / `cert_name` paths
before starting hivemind-core. The plugin uses whatever files exist; it
does not regenerate if the files are already present.

```bash
# Example: copy certbot output
cp /etc/letsencrypt/live/myhub.example.com/fullchain.pem \
   ~/.local/share/hivemind/hivemind.crt
cp /etc/letsencrypt/live/myhub.example.com/privkey.pem \
   ~/.local/share/hivemind/hivemind.key
```

To rotate: replace the files and restart hivemind-core. The plugin reads
them once on startup.

## nginx reverse proxy

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name myhub.example.com;

    ssl_certificate     /etc/letsencrypt/live/myhub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/myhub.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

Set `trusted_proxy_cidrs: ["127.0.0.1/32"]` in hivemind-core config so the
plugin reads the real client IP from `X-Forwarded-For`.

## Firewall

The plugin binds to `0.0.0.0:5678` by default. Restrict access to the port
at the firewall level if you don't want arbitrary hosts to attempt connections:

```bash
# Allow only LAN
ufw allow from 192.168.0.0/16 to any port 5678
```

## Authoring a transport plugin

See [architecture.md](architecture.md#authoring-a-transport-plugin) for the
`NetworkProtocol` ABC and `pyproject.toml` entry-point registration pattern.
The HTTP and MQTT transports in this same cluster are concrete examples of
alternative transport implementations.
