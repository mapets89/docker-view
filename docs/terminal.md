# Terminal lifecycle

The browser creates a terminal using a CSRF-protected Server request. The Server binds a random session ID to user, container, shell, timestamps, status, and expiry in SQLite. Attach requires the same active user, exact Origin, CSRF token, permission, current policy decision, and a non-system container.

The Server asks the Gateway for an allowlisted exec. The Gateway re-inspects the container, creates TTY exec with stdin/stdout/stderr only, and issues a 30-second single-use ticket. The two WebSockets proxy bounded binary input/output and bounded JSON resize messages. Disconnect closes both sockets/attach and writes duration-only audit; terminal stdin is never logged.

`auto` probes `/bin/bash`, `/bin/sh`, then `/bin/ash` with a bounded internal exec and opens the first available shell. Users may also explicitly choose from that allowlist. No arbitrary command or Docker option is accepted. Idle expiry is configurable; a closed or expired session cannot be reopened.
