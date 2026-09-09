# Troubleshooting

Use `docker compose ps` and `docker compose logs dockerview dockerview-gateway`. `/health` checks process liveness; `/ready` additionally checks SQLite and the Gateway/Engine path.

- Gateway unhealthy: confirm Docker is running and `DOCKER_GID` matches the socket group.
- Setup/login cookie missing: plain HTTP needs `DOCKERVIEW_COOKIE_SECURE=false`; HTTPS should use `true`.
- Terminal closes immediately: the selected shell may not exist; select `/bin/sh` and inspect the container state.
- Origin rejected: configure the exact scheme, host, and port in `DOCKERVIEW_ALLOWED_ORIGINS`.
- Empty stats: the container must be running and the Engine must provide cgroup metrics.

## Administration pages remain loading

Confirm that the running containers were rebuilt from the current source:

```bash
git pull --ff-only
docker compose up -d --build --force-recreate
curl --fail http://localhost:8080/ready
```

Then perform a hard browser refresh. Older builds could block the single SQLite connection while listing Users, Roles, or Policies, which also prevented account and subsequent administration requests from completing.

## Audit cannot list events

If the UI reports `Unable to list audit events`, rebuild from the current source as shown above. Audit metadata is stored as SQLite text and must be converted to JSON by the Server when records are read. Existing events remain in the `dockerview-data` volume.

## Policies reports `Cannot read properties of null`

This indicates an older build returned `null` for an empty policy collection. Current builds return an empty JSON array and defensively accept the legacy response. Rebuild the services and hard-refresh the page; no seed policy is required.

## Logout shows administrator setup again

If the login and administrator setup forms appear at the same time, the page layout CSS is overriding the browser's default styling for the HTML `hidden` attribute. Current builds explicitly enforce `[hidden] { display: none !important; }`. They also send `Cache-Control: no-store`, replace the authenticated history entry during logout, and refresh pages restored from the browser back-forward cache.

The Server remains authoritative: `/api/v1/status` only reports `needs_setup: true` when the user table is empty, and the bootstrap transaction refuses to create another initial administrator while any user exists.

## A page appears without styles after an update

Static frontend assets include content hashes in their filenames. A browser tab opened before a container rebuild may still request the previous hash. Current builds resolve that stale filename to the matching current asset and revalidate frontend assets, while genuinely unknown files return `404` instead of the login HTML.
