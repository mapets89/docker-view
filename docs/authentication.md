# Authentication

V1 uses `LocalAuthProvider`, behind a provider interface intended for later OIDC. Passwords are bounded to 1024 bytes, require 6 characters, and use Argon2id (64 MiB, three iterations, two lanes, random 16-byte salt). Hash parameters are parsed with upper bounds before verification.

Sessions use random 256-bit browser tokens; SQLite stores SHA-256 token hashes, expiry, revocation, source IP, and a hashed CSRF token. Cookies are `HttpOnly` for the session, `SameSite=Strict`, and `Secure` when configured. Logout revokes the server record. Admins can revoke all sessions for a user.

The first-user setup atomically creates an Admin only when `users` is empty. It cannot be used again and ships no default password.
