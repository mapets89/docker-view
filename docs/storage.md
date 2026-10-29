# Storage, backup, and restore

These procedures cover local, Development, QA, and laboratory deployments. They do not imply production support.

## Storage model

DockerView uses embedded SQLite through the Go application. There is no database service, database container, or `sqlite3` executable required at runtime. The Server owns the database connection; the Gateway does not read application data.

SQLite stores users, password hashes, roles, policies, settings, sessions, terminal-session records, and audit events. Docker Engine remains the source of truth for containers, images, networks, and runtime state; DockerView does not copy a permanent container inventory into SQLite.

| Workflow | SQLite location | Persistence |
|---|---|---|
| Compose | `/data/dockerview.db` inside `dockerview` | Named volume `dockerview_dockerview-data` |
| Local development (`make local`) | `.local/dockerview.db` in the repository | Local ignored directory |
| Standalone binary | `DOCKERVIEW_DB_PATH`, default `./dockerview.db` | Operator-managed file |

The Compose volume name comes from the project name declared in `compose.yml`. Confirm it rather than assuming it:

```bash
docker volume ls --filter label=com.docker.compose.project=dockerview
docker volume inspect dockerview_dockerview-data
```

On Docker Desktop for macOS or Windows, the volume's physical files live inside Docker Desktop's Linux VM. The `Mountpoint` returned by `docker volume inspect` is not normally a host path that should be edited directly.

The database file is created with mode `0600`. Treat every backup as sensitive: it contains password hashes, session records, authorization policy, settings, and audit history. Never commit a database or backup archive to the repository.

The generated Server-to-Gateway credential is separate, in `dockerview_dockerview-secrets`. It is not stored in SQLite and normally does not need to be migrated: a new deployment can generate a new credential shared by its Server and Gateway.

## Lifecycle

Removing or recreating the `dockerview` container does not remove SQLite because the named volume remains attached. These commands preserve data:

```bash
docker compose stop
docker compose down
docker compose up -d --build --force-recreate
```

This command is intentionally destructive because `-v` removes both named volumes:

```bash
docker compose down -v
```

It deletes users, sessions, settings, policies, audit history, and the generated Gateway credential. Do not use it for a normal update.

## Consistent Compose backup

Stop only the Server before copying the volume. This closes SQLite and avoids copying the database while a WAL transaction is active; the Gateway can remain running.

```bash
docker compose stop dockerview

docker run --rm \
  -v dockerview_dockerview-data:/data:ro \
  alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
  tar -czf - -C /data . > /absolute/private/path/dockerview-data-YYYYMMDD.tar.gz

docker compose start dockerview
curl --fail http://localhost:8080/ready
```

Replace the absolute backup path and filename before running the command. Store the archive outside the repository, restrict access to it, and verify that it is non-empty before relying on it.

## Compose restore

Restore only from a trusted archive. This procedure replaces the current contents of the data volume, so first create and verify a backup of the current state.

```bash
docker compose stop dockerview

docker run --rm \
  -v dockerview_dockerview-data:/data \
  -v /absolute/private/path:/backup:ro \
  alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
  sh -c 'find /data -mindepth 1 -maxdepth 1 -delete && tar -xzf /backup/dockerview-data-YYYYMMDD.tar.gz -C /data && chown -R 10001:10001 /data'

docker compose start dockerview
docker compose ps
curl --fail http://localhost:8080/ready
```

The fixed deletion target is the mounted DockerView data volume at `/data`; do not replace it with a host directory or a broader path. After startup, verify login, Settings, Policies, and Audit before discarding the pre-restore backup.

## Local-development backup

Stop `make local` with `Ctrl+C` before copying `.local/dockerview.db`. After the processes exit, copy that file to a private location. Restore it only while local mode is stopped, then start `make local` again.

For emergency Administrator password recovery, use the supported host command instead of editing SQLite directly. See [Authentication](authentication.md#password-recovery).
