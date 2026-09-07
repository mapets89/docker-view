# Docker Gateway

The Gateway uses the supported Moby Go modules (`client v0.6.0`, `api v1.56.0`) rather than invoking the Docker CLI. Routes are fixed in code; callers cannot provide an HTTP method, Docker API path, mounts, devices, capabilities, user, working directory, environment, privileged mode, or arbitrary command.

Gateway authentication requires a secret of at least 32 characters and uses constant-time comparison. Compose creates a 48-byte random secret in a dedicated volume. The health endpoint is process-only; readiness checks Engine connectivity but returns no Engine details.

The Gateway must never be published. Access to the Docker socket is effectively a highly privileged capability. If the Gateway is compromised, the Docker host must be considered potentially compromised.
