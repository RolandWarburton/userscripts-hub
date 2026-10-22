# userscripts

A small Go server that hosts private Tampermonkey userscripts, so installs update themselves.

## How it works

- Each script lives in `scripts/<name>.user.js` and gets a random read key in `keys/<name>`.
- Tampermonkey installs from `https://<DOMAIN>/<name>.user.js?auth=KEY`. The server adds
  `@updateURL` and `@downloadURL` (both carrying the key) when it serves the script, so later
  versions arrive automatically. Without the right key, every request gets the same 404.
- Scripts are published through an admin API (`/api/scripts`, Bearer `ADMIN_TOKEN`) or, optionally,
  an MCP server for claude.ai (`/mcp`, sign-in through Dex). A new upload must have a higher
  `@version` than the stored one, because Tampermonkey ignores anything else.
- Every write is logged and, if configured, sent to ntfy.

Diagrams: `calls.d2` (what calls what), `flows.d2` (request sequences), `components.d2` (overview).
Render with `d2 <file>.d2`.

## Prerequisites for hosting

- Docker with Compose.
- Traefik on the same host, with a `websecure` entrypoint, a `letsencrypt` cert resolver, and an
  external Docker network called `services`.
- A DNS name (`DOMAIN`) pointing at that host.
- Optional: an ntfy topic and token for write alerts.
- Optional, for the MCP server: a Dex instance with a `userscripts-mcp` client that claude.ai can
  sign in through.

## Running it

```sh
cp .env.example .env            # set DOMAIN and ADMIN_TOKEN (openssl rand -base64 32)
mkdir -p scripts keys && chown 1000:1000 scripts keys
docker compose up -d --build
```

Publish a script:

```sh
curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  --data-binary @my-script.user.js https://$DOMAIN/api/scripts/my-script
```

The response includes `install_url`. Open it in a browser that has Tampermonkey to install the script.
