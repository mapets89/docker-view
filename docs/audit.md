# Audit events

DockerView Audit is a security and accountability trail, not an HTTP access log. Events should represent an explicit user action, a security-relevant outcome, or a state mutation that an operator may need to investigate later.

## Recorded

- Authentication bootstrap, successful login, failed or rate-limited login, logout, and emergency password recovery
- User, role, policy, and settings mutations, including session invalidation and password reset
- Explicit container inspection initiated with the Inspect action
- Snapshot or live container-log access
- Secret reveal, recorded separately from ordinary masked inspection
- Container restart success or failure
- Terminal start and end, without recording stdin or terminal output
- Server-side policy denials for explicit operations

## Not recorded

- Overview and container inventory fetches
- Automatic runtime-risk enrichment used to render tables
- CPU and memory polling
- Read-only listing of Users, Roles, Permissions, Policies, Settings, or Audit
- Health, readiness, session hydration, and frontend refresh requests

Background UI fetches must use endpoints that do not emit success events. A background request denied by resource policy is also omitted because it does not represent an attempted human action. Authorization is still enforced and the browser receives the denial.

Audit metadata is structured and intentionally excludes passwords, session tokens, CSRF values, Gateway credentials, terminal input/output, and revealed secret values. SQLite retains up to 100,000 newest events. Audit is read-only through the API but is not non-repudiation: a host or storage compromise can alter the SQLite file.
