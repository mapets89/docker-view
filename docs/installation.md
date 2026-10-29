# Installation

For a local Docker installation, run:

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
curl --fail http://localhost:8080/ready
```

Create the first administrator with `docker compose exec dockerview dockerview-server bootstrap --username ADMIN`, then open <http://localhost:8080>. The port binds to localhost. The example environment uses `DOCKERVIEW_COOKIE_SECURE=false` for local HTTP. For remote access, use a TLS reverse proxy, set `DOCKERVIEW_COOKIE_SECURE=true`, and configure the exact HTTPS origin before exposing the proxy. The secret init service runs once, while named volumes retain SQLite and Gateway credentials.

On Linux, obtain the socket group with `stat -c '%g' /var/run/docker.sock` and set `DOCKER_GID` if it is not `0`. Do not solve socket permissions with `privileged: true` or a world-writable socket. For remote access, use a TLS reverse proxy and a private/VPN network.

Use `docker compose logs -f` to follow logs and `docker compose down` to stop DockerView without deleting its data. For source development and frontend hot reload, follow [Development](development.md).

## Updating

From the repository directory, update the source and recreate the services:

```bash
git pull --ff-only
docker compose up -d --build --force-recreate
docker compose ps
curl --fail http://localhost:8080/ready
```

The `dockerview-data` and `dockerview-secrets` named volumes are not removed by this procedure, so users, sessions, audit events, settings, policies, and the Gateway credential are preserved. Do not run `docker compose down -v` during a normal update because `-v` deletes those volumes. See [Storage, backup, and restore](storage.md) for database locations, Docker Desktop behavior, and safe backup/restore procedures.
