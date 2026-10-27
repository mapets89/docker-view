# Changelog

All notable changes are documented here. This project follows Keep a Changelog conventions and intends to use semantic versioning.

## [Unreleased]

### Added

- Initial DockerView V1 implementation: split Server/Gateway architecture, local auth, sessions, RBAC, policies, audit, inspection, stats, risk analysis, masked environment and inspect, SSE logs, xterm terminal, admin UI, hardened Compose, CI, tests, and security documentation.
- Added immutable `dockerview.protected=true` enforcement for sensitive containers, blocking exec and restart for every user at both the Server and Gateway layers.

### Changed

- Redesigned the container inventories with responsive table and card layouts, and added sorting by container, status, resources, and risk to both Overview and Containers.

### Fixed

- Updated golangci-lint Action to the signed `v9.3.0` commit, which runs on Node.js 24 instead of the deprecated Node.js 20 runtime.
- Updated CI and Docker builders to Go 1.26.10 to address `GO-2026-6809` in the standard library's `crypto/x509` certificate verification.
- Removed brittle Alpine package revision pins while retaining digest-pinned base images and vulnerability scanning.
- Updated Astro and patched frontend transitive dependencies so `npm audit --audit-level=high` reports no vulnerabilities.
- Updated runtime images to Alpine 3.24.2 to include patched OpenSSL packages and clear `CVE-2026-14456`.
- Pinned Trivy Action to the signed `v0.36.0` commit after the legacy unprefixed release reference stopped resolving in GitHub Actions.
- Prevented Users, Roles, and Policies listings from deadlocking when SQLite uses a single connection.
- Corrected audit metadata decoding from SQLite text values so existing events can be listed.
- Standardized empty administrative collections as JSON arrays instead of `null`, with defensive handling in the Policies and Audit UI.
- Prevented the login and first-run forms from appearing simultaneously by enforcing the HTML `hidden` state, while keeping authentication pages and status responses uncached.
- Added compatibility resolution for stale hashed frontend assets across container rebuilds, and return `404` for unknown static files instead of login HTML.
