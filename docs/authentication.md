# Authentication

V1 uses `LocalAuthProvider`, behind a provider interface intended for later OIDC. Passwords are bounded to 1024 bytes, require 6 characters, and use Argon2id (64 MiB, three iterations, two lanes, random 16-byte salt). Hash parameters are parsed with upper bounds before verification.

Five failed sign-in attempts for the same username and source IP trigger a 20-second cooldown. The fifth failure returns `429 Too Many Requests` with `Retry-After`, successful authentication clears the failure count, and blocked attempts are written to the audit log. The limiter is in memory and resets when the Server restarts.

Sessions use random 256-bit browser tokens; SQLite stores SHA-256 token hashes, expiry, revocation, source IP, and a hashed CSRF token. Cookies are `HttpOnly` for the session, `SameSite=Strict`, and `Secure` when configured. Logout revokes the server record. Admins can revoke all sessions for a user.

The first-user setup atomically creates an Admin only when `users` is empty. It cannot be used again and ships no default password.

## Password recovery

An authenticated Administrator can change another local user's password from Administration → Users. If access to the only Administrator is lost, run the host-authorized recovery command from the repository directory:

```bash
docker compose exec dockerview dockerview-server reset-password --username USERNAME
```

The command requires an interactive terminal, reads and confirms the new password without echoing it, applies the normal password policy and Argon2id hashing, revokes every existing session for the account, and records `PASSWORD_RECOVERY` in Audit. It does not accept a password through flags or standard-input pipes. The account must still be enabled; a disabled account requires another Administrator to enable it.

Docker host and volume access are the recovery authority. DockerView deliberately exposes no unauthenticated password-reset endpoint and does not require email or SMTP.
