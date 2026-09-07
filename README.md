# DockerView

DockerView is a lightweight, self-hosted interface for Docker inspection and controlled troubleshooting. It gives development, QA, and internal operations teams visibility into containers without Linux accounts, SSH keys, Docker group membership, or direct Docker Engine access.

> [!WARNING]
> Access to the Docker socket is effectively a highly privileged capability. Compromise of the Docker Gateway must be considered potential compromise of the Docker host. DockerView V1 is primarily intended for development and laboratory environments.

## Features

- Container inventory, status, health, ports, networks, mounts, environment, raw inspect, stats, PIDs, and uptime
- Runtime configuration risk assessment (not image CVE scanning)
- Secret masking with permission-gated, audited reveal
- Snapshot and live SSE logs
- Audited xterm.js terminal over WebSocket, with allowlisted shells, bounded resize, ownership, expiry, and cleanup
- Local Argon2id authentication, hashed server-side sessions, strict cookies, CSRF protection, and rate limits
- Permission-based RBAC with Viewer, Developer, and Admin seed roles
- Resource policies by container name glob or exact label; deny overrides allow
- User, role, policy, settings, and SQLite audit administration
- Separate, authenticated, allowlist-only Docker Gateway

## Architecture

```text
Browser :8080
   │ cookies + CSRF / SSE / WebSocket
   ▼
DockerView Server ── private shared-secret API ──► Docker Gateway
   │ SQLite                                      │ explicit operations only
   ▼                                             ▼
persistent data                              /var/run/docker.sock
```

The Server never mounts or accesses `docker.sock`. The Gateway has no frontend, user database, generic proxy, or published host port. Both application containers carry `dockerview.system=true`; DockerView refuses exec and restart against any container with that label, including for Admins.

See [architecture](docs/architecture.md), [security model](docs/security.md), [threat model](docs/threat-model.md), and the documented [V1 implementation decisions](docs/decisions.md).

## Requirements

- Docker Engine 24+ with Compose v2
- For source development: Go 1.25+, Node 22+, npm 11+
- Linux deployments may need `DOCKER_GID` set to the numeric group owner of `/var/run/docker.sock`

## Quick start

```bash
git clone https://github.com/mapets89/docker-view.git dockerview
cd dockerview
cp .env.example .env
docker compose up -d --build
```

Open <http://localhost:8080>. On first launch, DockerView displays a one-time setup that creates the first Administrator. There are no default credentials. The bootstrap endpoint atomically disables itself as soon as the first account exists.

The internal Gateway secret is generated automatically with 48 random bytes and persisted in the `dockerview-secrets` volume. To supply your own, use `DOCKERVIEW_GATEWAY_SECRET` outside Compose or mount a file and set `DOCKERVIEW_GATEWAY_SECRET_FILE`.

## Configuration

Copy `.env.example`; common settings include the public port, instance/environment labels, session and terminal TTLs, default log tail, cookie security, allowed browser origins, and socket group ID. See [configuration](docs/configuration.md). For HTTPS, terminate TLS at a trusted reverse proxy, set `DOCKERVIEW_COOKIE_SECURE=true`, and set the exact HTTPS origin.

## Authentication and authorization

Local authentication uses Argon2id. Session identifiers are random and stored only as SHA-256 hashes; sessions are server-side, expiring, revocable, and use `HttpOnly`, `SameSite=Strict` cookies. CSRF tokens and exact Origin checks protect mutations and terminal WebSockets.

Viewer can read containers, stats, inspect, and logs. Developer adds `container.exec`. Admin receives the complete code-defined permission catalog. Roles grant actions; policies restrict matching resources. System policy is always highest priority, followed by explicit deny, explicit allow, role permission, and default deny. See [authorization](docs/authorization.md).

`container.exec` is privileged: a user who can exec can potentially retrieve secrets from inside the container even without `secret.view`.

## Development, build, and testing

```bash
make dev
make build
make test
make lint
make typecheck
make security
```

The production frontend is a static Astro build served by Go; Node is not present at runtime. The pinned frontend uses Astro 7.3.1 and the native Go TypeScript 7.0.2 compiler. Because TypeScript 7.0 has no programmatic API and Astro's template checker still needs one, `astro check` uses the official `@typescript/typescript6` 6.0.2 compatibility package side-by-side; `npm run typecheck` is TS 7 and is mandatory. Details are in [development](docs/development.md).

Backend tests do not perform destructive host operations. Integration testing against a disposable container is opt-in. CI builds and checks Go, Astro/TypeScript, Docker images, Compose, dependencies, and filesystem/container vulnerabilities.

## Troubleshooting

- `permission denied` on `docker.sock`: set `DOCKER_GID` to `stat -c '%g' /var/run/docker.sock` (Linux), then recreate the Gateway.
- Login loops over plain HTTP: use the Compose default `DOCKERVIEW_COOKIE_SECURE=false`; enable it only behind HTTPS.
- WebSocket rejected: `DOCKERVIEW_ALLOWED_ORIGINS` must exactly match the browser origin.
- Readiness unhealthy: inspect `docker compose logs dockerview-gateway` and confirm Docker Engine is running.

See [troubleshooting](docs/troubleshooting.md).

## Screenshots

Screenshots will be added after the first public preview. The implemented UI is dark-first, responsive, keyboard-accessible, and uses an original layered-container visual identity.

## Roadmap and contribution status

Projects, Compose grouping, multi-host, OIDC/Keycloak, mTLS, external audit sinks, read-only mode, and production hardening are future work; see the [roadmap](docs/roadmap.md).

DockerView is not accepting external pull requests at this time. It remains readable, forkable, and usable under the [Apache License 2.0](LICENSE). Security reports are welcome through the private process in [SECURITY.md](SECURITY.md).
