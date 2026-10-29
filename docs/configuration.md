# Configuration

## Compose configuration

Copy `.env.example` to `.env` before starting Compose. These values are interpolated by `compose.yml`:

| Variable | Local default | Purpose |
|---|---|---|
| `DOCKERVIEW_PORT` | `8080` | Published web port |
| `DOCKERVIEW_INSTANCE_NAME` | `DockerView` | Initial UI instance label |
| `DOCKERVIEW_ENVIRONMENT` | `DEV` | Initial environment label |
| `DOCKERVIEW_SESSION_TTL` | `12h` | Login session lifetime |
| `DOCKERVIEW_TERMINAL_IDLE_TIMEOUT` | `15m` | Initial terminal session expiry |
| `DOCKERVIEW_LOG_TAIL_DEFAULT` | `500` | Initial log line count |
| `DOCKERVIEW_COOKIE_SECURE` | `false` | Set to `true` only when browsers use HTTPS |
| `DOCKERVIEW_SECRET_MASKING` | `true` | Global upper bound for secret masking |
| `DOCKERVIEW_ALLOWED_ORIGINS` | `http://localhost:8080` | Exact comma-separated browser origins |
| `DOCKER_GID` | `0` | Docker socket group supplied to the non-root Gateway |

Compose fixes internal listen addresses, filesystem paths, and the private Gateway URL. Changing similarly named standalone-binary variables in `.env` does not override those internal Compose values.

The internal Gateway secret is generated into the `dockerview-secrets` volume. Do not add a secret to `.env`, commit `.env`, or copy credential volumes into the repository.

## Standalone binaries

The Go binaries additionally support:

| Variable | Binary default | Purpose |
|---|---|---|
| `DOCKERVIEW_LISTEN_ADDR` | `:8080` | Server listen address |
| `DOCKERVIEW_GATEWAY_LISTEN_ADDR` | `:8081` | Gateway listen address |
| `DOCKERVIEW_DB_PATH` | `./dockerview.db` | SQLite database path |
| `DOCKERVIEW_STATIC_DIR` | `../frontend/dist` | Built frontend directory |
| `DOCKERVIEW_GATEWAY_URL` | `http://127.0.0.1:8081` | Private Gateway URL used by the Server |
| `DOCKERVIEW_GATEWAY_SECRET` | none | Shared secret, at least 32 characters |
| `DOCKERVIEW_GATEWAY_SECRET_FILE` | none | File containing the shared secret |
| `DOCKERVIEW_MAX_BODY_BYTES` | `1048576` | Maximum request body size |

There is no insecure Gateway-secret default. Both binaries must receive the same strong value through either the string or file setting. The native launcher described in [Development](development.md) handles this automatically.

## Persisted administration settings

On first start, the instance name, environment, terminal idle timeout, default log tail, and secret-masking value are copied into SQLite. Later changes made in Administration → Settings are persistent and take precedence over their initial environment values. Restarting with a changed `.env` does not overwrite an existing stored setting.

Global `DOCKERVIEW_SECRET_MASKING=false` is an upper bound: disabling masking in the database cannot bypass the server configuration or grant `secret.view`.

## Protecting sensitive containers

Add `dockerview.protected: "true"` to a service's Compose labels to prevent terminal access and restarts through DockerView for every user, including Admins. Inspection, metrics, and logs remain available. Docker labels are fixed when a container is created, so apply the change with `docker compose up -d --force-recreate <service>`.
