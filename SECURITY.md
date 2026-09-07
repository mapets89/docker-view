# Security policy

## Supported versions

Until the first stable release, only the latest commit on the default branch is supported with security fixes.

## Assumptions and scope

DockerView V1 is primarily intended for development and laboratory environments. It is not represented as production-hardened or zero-trust. Place it behind TLS and an access-controlled network; do not expose it directly to the public Internet.

Access to the Docker socket is effectively a highly privileged capability. The Gateway is the privileged trust boundary and the only component mounting the socket. Its private network, shared-secret authentication, fixed operation allowlist, system-container protection, input bounds, and non-root/hardened container reduce exposure but cannot make socket access safe after Gateway compromise.

**Compromise of the Docker Gateway must be considered potential compromise of the Docker host.**

The Server holds SQLite authorization state. A complete Server compromise can alter users, roles, policies, sessions, and local audit records, but does not itself provide the socket; defensive Gateway restrictions still apply. SQLite audit is operational evidence, not immutable non-repudiation.

Docker Exec is privileged. A user with `container.exec` can potentially retrieve environment or filesystem secrets from inside an allowed container, bypassing UI masking. Grant it sparingly. `secret.view` reveal is separately enforced and audited.

## Reporting a vulnerability

Do not open a public issue containing exploit details. Contact the maintainers privately using the security contact published with the repository or GitHub's private vulnerability reporting feature. Include affected revision, impact, minimal reproduction, and suggested mitigation. Expect acknowledgement within seven days. Never test against systems you do not own or operate with explicit permission.
