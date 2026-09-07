# Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DOCKERVIEW_PORT` | `8080` | Published web port |
| `DOCKERVIEW_INSTANCE_NAME` | `DockerView` | UI instance label |
| `DOCKERVIEW_ENVIRONMENT` | `DEV` | Environment label |
| `DOCKERVIEW_SESSION_TTL` | `12h` | Login session lifetime |
| `DOCKERVIEW_TERMINAL_IDLE_TIMEOUT` | `15m` | Terminal session expiry |
| `DOCKERVIEW_LOG_TAIL_DEFAULT` | `500` | Initial log lines |
| `DOCKERVIEW_COOKIE_SECURE` | `false` in local Compose | Enable behind HTTPS |
| `DOCKERVIEW_ALLOWED_ORIGINS` | `http://localhost:8080` | Exact comma-separated browser origins |
| `DOCKER_GID` | `0` | Socket group supplied to non-root Gateway |

Runtime binaries also support `DOCKERVIEW_GATEWAY_SECRET` or `DOCKERVIEW_GATEWAY_SECRET_FILE`; no insecure default exists. Do not commit `.env` or credential volumes.
