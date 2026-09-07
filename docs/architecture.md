# Architecture

DockerView is one repository and one Compose deployment with two runtime binaries. `dockerview-server` owns HTTP, static Astro assets, local authentication, sessions, RBAC, policies, settings, audit, SQLite, and proxying. `dockerview-gateway` alone owns Docker Engine SDK access.

The Server joins a public bridge for its published port and a private `internal: true` bridge for Gateway traffic. The Gateway only joins the private bridge and publishes no port. Requests use a generated shared secret in `X-DockerView-Gateway-Secret`; the Gateway compares it in constant time and accepts only explicit typed routes. The design can replace this transport with mTLS without changing RBAC or sessions.

Docker is the source of truth for runtime metadata. SQLite stores identities and control-plane state, never a permanent container inventory. Scope columns are currently `host/local`, leaving room for later project or host scopes without exposing Projects in V1.

The Astro 7 frontend builds to static files. Go serves those files and `/api/v1`; production does not run Node. Logs travel one-way with SSE and terminals use WebSocket only where bidirectional I/O is required.
