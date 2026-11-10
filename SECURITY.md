# Security

## Serving scripts

- Each script gets a random read key in `keys/<name>`. Tampermonkey installs from
  `https://<DOMAIN>/<name>.user.js?auth=KEY`, and the server adds `@updateURL` and `@downloadURL`
  (both carrying the key) when it serves the script. Without the right key, every request gets the
  same 404, so a script's existence isn't revealed.
- Scripts can only be changed through the dashboard or the MCP server. Both sign in through Dex, and
  both admit only the emails in `MCP_ALLOWED_EMAILS`.
- Every write is logged with the user who made it and, if configured, sent to ntfy.

## The dashboard

oauth2-proxy (the `userscripts-admin` service) sits in front of `ADMIN_DOMAIN`. It signs the
browser in with Dex (Dex client `userscripts-web`) and forwards each request to the server with the
Dex access token attached. The server checks that token with Dex on every request: it must have
been issued to `userscripts-web`, and its email must be in `MCP_ALLOWED_EMAILS`. Anyone else who
signs in gets a 403 page. The MCP server only accepts tokens issued to `userscripts-mcp`, so a
token for one can't be used on the other.

Sessions last 12 hours and are never renewed silently. The cookie is `__Host-` prefixed,
`Secure`, `HttpOnly` and `SameSite=Strict`, and writes must also carry an `X-Requested-With`
header. The page loads nothing from other origins and runs under a strict CSP.
