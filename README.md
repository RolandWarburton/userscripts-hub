# userscripts

A small Go server that hosts private Tampermonkey userscripts, so installs update themselves.

<p align="center">
  <img src="screenshots/02-script-open.png" alt="The dashboard in light mode, with a script open in the editor" width="48%">
  &emsp;
  <img src="screenshots/07-dark.png" alt="The dashboard in dark mode, with a script open in the editor" width="48%">
</p>

## Prerequisites for hosting

- Docker with Compose.
- Traefik on the same host, with a `websecure` entrypoint, a `letsencrypt` cert resolver, and an
  external Docker network called `services`.
- Two DNS names pointing at that host: `DOMAIN` for scripts and the MCP server, `ADMIN_DOMAIN` for
  the dashboard.
- A Dex instance with:
  - a confidential client `userscripts-web` whose redirect URI is
    `https://<ADMIN_DOMAIN>/oauth2/callback`, for the dashboard;
  - optionally, for the MCP server, a public client `userscripts-mcp` that claude.ai can sign in
    through.
- Optional: an ntfy topic and token for write alerts.

## Running it

```sh
cp .env.example .env            # set the domains, Dex issuer, allowed emails and secrets
mkdir -p scripts keys && chown 1000:1000 scripts keys
docker compose up -d --build
```

Then open `https://<ADMIN_DOMAIN>/`, sign in, and create a script. Open its install URL in a
browser with Tampermonkey to install it. See [SECURITY.md](SECURITY.md) for how access works.
