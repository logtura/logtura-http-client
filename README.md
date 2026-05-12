# logtura-http-client

An `http_client`-shaped HTTP poller with built-in OAuth refresh, distributed as a small static binary you run from Vector's `exec` source.

Vector's [`http_client`](https://vector.dev/docs/reference/configuration/sources/http_client/) source only supports static bearer tokens — there is no way to refresh credentials without restarting Vector. That's a problem for any endpoint that issues short-lived access tokens (OAuth-protected analytics APIs, internal services behind a token mint, etc.). This binary fills the gap until [vectordotdev/vector#17192](https://github.com/vectordotdev/vector/discussions/17192) lands upstream.

## What it does

1. Reads a TOML config file with a shape that mirrors Vector's `http_client`.
2. Acquires a bearer token via one of three strategies:
   - `bearer` — static token, same as upstream.
   - `bearer_refresh` — POST to a configurable URL for a fresh `{access_token, expires_in}`. The caller's backend (e.g. your SaaS) does the heavy OAuth lifting; this binary just asks for a token.
   - `oauth_refresh` — RFC 6749 directly. You hold `client_id`/`client_secret`/`refresh_token`. Rotated refresh tokens persist to a configurable file path.
3. Polls the configured endpoint on a schedule.
4. Extracts an array of rows from each response via JSONPath.
5. Emits each row as a newline-delimited JSON line on stdout.
6. Tracks a cursor — the last row's timestamp (or any JSONPath you specify) — and substitutes `{cursor}` into the URL/query of the next request, so each poll fetches only what's new.

On a 401, it refreshes the token and retries once. On repeated auth failure, it exits with code 2 so the parent (Vector's `exec` source) can restart it with fresh state.

## Usage with Vector

```yaml
sources:
  my_source:
    type: exec
    command: ["logtura-http-client", "--config", "/etc/logtura/source.toml"]
    mode: streaming
    decoding: { codec: json }
    framing: { method: newline_delimited }
```

## Example config

```toml
endpoint = "https://api.example.com/v1/logs?since={cursor}"
scrape_interval_secs = 30

[headers]
accept = "application/json"

[auth]
strategy = "bearer_refresh"
token_url = "https://your-saas.example.com/api/tail/token"

[auth.token_headers]
authorization = "Bearer ${TAIL_TOKEN}"

[cursor]
json_path = "$.events[-1].ts"
init = "now - 90s"

[rows]
json_path = "$.events"
```

`${TAIL_TOKEN}` is substituted from the process environment before the TOML is parsed. Use this for secrets; everything else stays declarative on disk.

## Installation

Pre-built static binaries are attached to each GitHub Release. The Linux musl build runs on Alpine, Debian, Ubuntu, and most Docker images:

```bash
curl -L https://github.com/logtura/logtura-http-client/releases/latest/download/logtura-http-client-x86_64-unknown-linux-musl \
  -o /usr/local/bin/logtura-http-client
chmod +x /usr/local/bin/logtura-http-client
```

Or build from source:

```bash
cargo install --git https://github.com/logtura/logtura-http-client
```

## Auth strategies in detail

### `bearer_refresh`

Your backend exposes `POST /token` that takes some caller-supplied auth (typically a long-lived JWT in `Authorization`) and returns a fresh access token:

```json
{ "access_token": "eyJ…", "expires_in": 3600 }
```

The binary caches the access token until 60 seconds before expiry, then re-fetches. Your backend keeps the rotation-prone refresh token in a database where you can update it atomically.

### `oauth_refresh`

You give the binary all three OAuth secrets: `client_id`, `client_secret`, `refresh_token`. It runs the RFC 6749 refresh-token grant directly against your provider's token endpoint.

If the provider rotates refresh tokens (Supabase, Auth0), set `refresh_token_file` to a path on a persistent volume. The binary writes the new refresh token to that file atomically after every refresh, and reads from the file (falling back to config) on every refresh. Without a file, the binary will log a warning each rotation and you'll have to manually reconnect every refresh — fine for dev, broken in production.

### Choosing between them

- **Use `bearer_refresh` when** you have a backend you control. Cleaner secret handling (provider secrets never touch the deployed container), centralized rotation, no on-disk state needed.
- **Use `oauth_refresh` when** you want zero backend dependency. Pure OAuth at the cost of a writable volume.

## Status

Built for [logtura](https://github.com/logtura/logtura)'s Supabase log forwarder, where Supabase rotates refresh tokens on every use and Vector can't keep up. The shape is intentionally generic — any OAuth-protected endpoint with a JSON response is supported.

## License

Apache-2.0.
