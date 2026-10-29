# Development

DockerView distinguishes the local workstation from shared non-production environments. Local mode favors rapid iteration and frontend hot reload. Development mode builds and runs the release images and security boundaries used in Development or QA. DockerView is not recommended for production deployments.

## Requirements

- Docker Engine 24+ with Compose v2, running and accessible by the current user
- Go 1.25 or newer
- Node.js 22 or newer and npm 11 or newer
- `openssl` and `curl`

The repository pins application dependencies in `backend/go.sum` and `frontend/package-lock.json`. Container builders and runtime base images are pinned by digest.

## Local development with hot reload

Install the exact frontend dependencies and download the Go modules once:

```bash
make local-setup
```

Start the Gateway, Server, and Astro development server together:

```bash
make local
```

For a fresh local database, create the first administrator in another terminal, from the project directory:

```bash
cd backend
DOCKERVIEW_DB_PATH=../.local/dockerview.db go run ./cmd/server bootstrap --username ADMIN
```

Replace `ADMIN` with the desired username. The command prompts for the password and confirmation; it succeeds only when no user exists. If using `DOCKERVIEW_LOCAL_STATE_DIR`, set `DOCKERVIEW_DB_PATH` to `dockerview.db` in that directory instead.

Open <http://localhost:4321> and sign in. Astro reloads frontend changes automatically. Its development proxy forwards `/api`, SSE, and terminal WebSockets to the Go Server at `127.0.0.1:8080`. The Server talks to the Gateway at `127.0.0.1:8081`.

In local mode the backend does not serve the compiled frontend on port 8080; use Astro on port 4321. Compose serves the built frontend from the server on port 8080.

The launcher generates an ephemeral shared Gateway secret, stores SQLite state below `.local/`, waits for both Go services to become ready, and stops all child processes on `Ctrl+C`. It does not modify `.env` or the Compose volumes. To reset only local-development state, stop the launcher and remove `.local/`.

Go source changes require restarting `make local`; frontend changes do not. Docker Engine must remain running because the local Gateway connects through the Docker client configuration. On Linux, the current user needs permission to access `/var/run/docker.sock`.

Advanced overrides:

```bash
DOCKERVIEW_LOCAL_STATE_DIR=/tmp/dockerview-local make local
DOCKERVIEW_GATEWAY_SECRET="$(openssl rand -hex 32)" make local
```

## Development environment

Run:

```bash
cp .env.example .env
make dev
```

`make dev` uses the base `compose.yml`, builds the release static frontend and Go binaries, and keeps logs attached to the terminal. It intentionally has no hot reload or source mounts. Configure the public port, browser Origin, HTTPS cookie policy, instance name, and environment label through the environment-specific `.env` before deploying it to a shared Development or QA host. This workflow does not imply production support.

Compose stores the database and generated Gateway credential in named volumes. `docker compose down` preserves them. `docker compose down -v` is an explicit destructive reset of users, sessions, audit events, settings, policies, and the generated credential.

## Required checks

Before committing a change, run:

```bash
make test
make lint
make typecheck
make security
docker compose config
docker compose build dockerview dockerview-gateway
```

`make security` always runs `npm audit`; it also runs `govulncheck` and Trivy when they are installed locally, while CI always runs the complete scanner set. The unit tests do not execute destructive Docker operations. Integration testing against a disposable container remains opt-in.

TypeScript 7.0 does not expose a programmatic compiler API, while Astro's checker still requires one. `@typescript/native` supplies the TypeScript 7 compiler and the `typescript` alias supplies `@typescript/typescript6` only to template and lint tooling. `npm run check` runs both Astro checking and native TypeScript checking.
