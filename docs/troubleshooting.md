# Troubleshooting

Use `docker compose ps` and `docker compose logs dockerview dockerview-gateway`. `/health` checks process liveness; `/ready` additionally checks SQLite and the Gateway/Engine path.

- Gateway unhealthy: confirm Docker is running and `DOCKER_GID` matches the socket group.
- Setup/login cookie missing: plain HTTP needs `DOCKERVIEW_COOKIE_SECURE=false`; HTTPS should use `true`.
- Terminal closes immediately: the selected shell may not exist; select `/bin/sh` and inspect the container state.
- Origin rejected: configure the exact scheme, host, and port in `DOCKERVIEW_ALLOWED_ORIGINS`.
- Empty stats: the container must be running and the Engine must provide cgroup metrics.
