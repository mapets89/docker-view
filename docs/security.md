# Security architecture and adversarial review

The Docker Gateway is a privileged security boundary. It is deliberately small, has no database or UI, does not expose a generic Docker API, and allowlists list, inspect, stats, logs, restart, and constrained exec. It validates container identifiers, inspects containers before actions, rejects `dockerview.system=true`, limits bodies/tail/resize/messages, permits only `/bin/bash`, `/bin/sh`, and `/bin/ash`, uses one-time short-lived attach tickets, and sanitizes Docker errors.

The Server independently enforces authentication, code-defined permissions, resource policies, immutable system policy, terminal ownership/expiry, CSRF, exact WebSocket Origin, request bounds, and rate limits. Raw inspect and environment views share the same masking traversal. Reveal needs `secret.view` server-side and creates `SECRET_REVEAL` audit.

Compose drops all capabilities, enables no-new-privileges and read-only roots, uses non-root users, tmpfs for `/tmp`, and mounts `docker.sock` only into the private Gateway. The SQLite file is `0600` in a separate volume. For Linux socket access, set `DOCKER_GID` rather than running privileged.

## Final adversarial review

Reviewed paths: socket exposure, endpoint discovery, shared-secret timing/absence, Docker errors, container ID injection, generic passthrough, system-label spoofing, policy precedence/glob behavior, missing permission elevation, bootstrap races, password resource abuse, session fixation/replay/revocation, CSRF, CSWSH/Origin, terminal ownership/replay/resize/message bounds/cleanup, SSE cancellation, raw inspect masking, audit content, traversal/static serving, SQLite exposure, headers, and Compose privileges.

Findings fixed during implementation:

- **High — Cross-user terminal attach:** terminal IDs are verified against the authenticated user and expiry before attach; Gateway tickets are random, private, 30-second, and single-use.
- **High — CSWSH:** WebSocket requires an authenticated strict cookie, exact allowlisted Origin, valid CSRF token, and immutable server-side container binding.
- **High — system-container mutation:** both Server policy and Gateway inspect the authoritative Docker label immediately before exec/restart. Admin cannot override it.
- **High — raw inspect secret bypass:** recursive masking covers `Config.Env` and sensitive keys; reveal is permission checked and audited.
- **High — masking-disable permission bypass:** disabling global masking no longer exposes values to users without `secret.view`; that permission remains an unconditional server-side boundary.
- **High — vulnerable runtime/dependency versions:** Trivy found fixable OpenSSL and `x/crypto` advisories during the final scan. Runtime packages are pinned to the fixed OpenSSL release and `x/crypto` was upgraded; the repeated image and filesystem scans report zero HIGH/CRITICAL findings.
- **High — root secret initializer:** the one-shot Compose initializer now runs as UID/GID 10003; the empty volume is populated with matching ownership and the generated file is read-only to runtime consumers.
- **Medium — proxy inheritance on the private channel:** Server HTTP and WebSocket clients explicitly disable environment proxies so the Gateway bearer secret cannot be redirected by proxy variables.
- **Medium — bootstrap race/default credentials:** conditional insert is serialized by SQLite's single connection; no defaults exist.
- **Medium — Docker error leakage:** Gateway returns stable errors and never forwards daemon messages to browsers.
- **Medium — resource exhaustion:** body, password, log tail, resize, WS message, session creation, login, and bootstrap limits were added; streams are context-cancelled and closed.
- **Low — static traversal:** paths are cleaned and joined below a fixed static root; `/api` never falls through to files.

Remaining accepted risks:

- **Critical by architecture:** a Gateway code-execution compromise can lead to Docker host compromise. The socket makes absolute isolation impossible.
- **High by granted capability:** exec users can read secrets/data accessible inside allowed containers and may exploit vulnerable/container-misconfigured workloads.
- **Medium:** the shared secret is bearer authentication; a Server compromise can use Gateway operations. mTLS is roadmap work.
- **Medium:** SQLite audit can be altered after Server/storage compromise and is not non-repudiation.
- **Low:** in-memory login limiting resets on restart and is per-instance; V1 is single-instance DEV/LAB software.
