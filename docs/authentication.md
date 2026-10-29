# Authentication

V1 uses `LocalAuthProvider`, behind a provider interface intended for later OIDC. Passwords are bounded to 1024 bytes, require 6 characters, and use Argon2id (64 MiB, three iterations, two lanes, random 16-byte salt). Hash parameters are parsed with upper bounds before verification.

Five failed sign-in attempts for the same username and source IP trigger a 20-second cooldown. The fifth failure returns `429 Too Many Requests` with `Retry-After`, successful authentication clears the failure count, and blocked attempts are written to the audit log. The limiter is in memory and resets when the Server restarts.

Sessions use random 256-bit browser tokens; SQLite stores SHA-256 token hashes, expiry, revocation, source IP, and a hashed CSRF token. Cookies are `HttpOnly` for the session, `SameSite=Strict`, and `Secure` when configured. Logout revokes the server record. Admins can revoke all sessions for a user.

The first-user setup atomically creates an Admin only when `users` is empty. It cannot be used again and ships no default password.
