# pi-session-share-server

A lightweight Go server for [pi-session-share](https://github.com/SunflowerFuchs/pi-session-share) — stores shared pi sessions as rendered HTML pages with optional password protection and configurable lifetimes.

## Quickstart

```bash
# Docker
docker compose up -d

# Or build from source
go build -o pi-session-share-server .
./pi-session-share-server --port 8080
```

## API

### Create Session

```
POST /api/sessions
```

```json
{
  "html": "<rendered HTML>",
  "password": "optional-viewing-password",
  "ttl_seconds": 86400
}
```

Returns:

```json
{
  "id": "a7Xk9mQ",
  "secret": "s3cr3t-t0k3n-for-update-delete",
  "expires_at": "2025-05-08T12:00:00Z",
  "url": "https://share.example.com/s/a7Xk9mQ"
}
```

### Update Session

```
PUT /api/sessions/{id}
Authorization: Bearer <secret>
```

Same body as create. Returns updated session.

### Delete Session

```
DELETE /api/sessions/{id}
Authorization: Bearer <secret>
```

Returns `204 No Content`.

### View Session

```
GET /s/{id}
```

- No password → serves the HTML directly
- Password set → shows a password form, sets an HMAC-signed cookie on success

### Authenticate

```
POST /s/{id}/auth
```

Accepts both `application/json` (`{"password": "..."}`) and `application/x-www-form-urlencoded` (`password=...`). Sets a cookie and redirects to the session page.

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--port` | `PORT` | `8080` | Listen port |
| `--db` | `DB_PATH` | `./sessions.db` | SQLite database path |
| `--base-url` | `BASE_URL` | *(auto)* | Base URL for share links — auto-detected from request headers, only needed as a fallback |
| `--cleanup-interval` | `CLEANUP_INTERVAL` | `5m` | Expired session cleanup interval |
| `--cookie-secret` | `COOKIE_SECRET` | *(random)* | HMAC key for auth cookies — auto-generated if not set, logged on startup |

## Docker

```bash
cp .env.example .env
# Edit .env if needed (usually the defaults work fine behind a reverse proxy)
docker compose up -d
```

The database is stored in a named Docker volume and persists across restarts.

## Reverse Proxy

Behind a reverse proxy (nginx, Caddy, Traefik, etc.), the server auto-detects its public URL from `Host` + `X-Forwarded-Proto` headers. No `BASE_URL` config needed in most setups.

Example Caddy config:

```
share.example.com {
    reverse_proxy localhost:8080
}
```

## Requirements

- Go 1.25+ (or Docker)
- No external dependencies (SQLite is embedded, no CGO)
