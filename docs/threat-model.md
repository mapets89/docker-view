# Threat model

| Attacker / threat | Attack path | Mitigation | Remaining risk |
|---|---|---|---|
| Unauthenticated remote attacker | Login guessing, bootstrap race, CSRF/CSWSH, oversized bodies | No defaults; atomic one-time bootstrap; Argon2id; rate limits; strict cookies; CSRF + Origin; body bounds | In-memory rate limit resets; deploy behind network/TLS controls |
| Malicious Viewer | Hidden-action/API bypass, inspect secret extraction | Every API checks backend permissions and policies; shared recursive masking; audited reveal | Visible non-secret runtime metadata may itself be sensitive |
| Malicious Developer | Exec into denied/system container, ticket theft, terminal exhaustion | Deny precedence; immutable system rule in both layers; owner-bound expiring session; one-use private ticket; limits and idle expiry | Exec can retrieve secrets and exercise the container's own privileges |
| Malicious Admin | Override system policy, erase audit | Gateway independently blocks system mutation; audit API is read-only | Admin controls local auth state; SQLite filesystem compromise can alter audit |
| Compromised Server | Direct socket use, arbitrary Docker request | No socket mount/client; private authenticated typed Gateway API | Bearer secret can authorize allowed Gateway actions; restart/exec remain dangerous |
| Compromised Gateway | Use mounted socket to control Engine/host | Small dependency/API surface, non-root, read-only, no-new-privileges, private network | Host must be considered potentially compromised |
| Container-name spoofing / glob bypass | Name selected to evade policy | Policies evaluate authoritative inspect name/labels, use bounded `path.Match`, reject `/` and bracket patterns | Simple glob language cannot express complex organizational intent |
| Secret leakage | Env/raw inspect/errors/logging/audit | Mask both views; sanitized errors; structured metadata excludes credentials/stdin | Application logs or exec output may naturally contain secrets |

Assets include the Docker host/socket, Gateway, Server, SQLite, sessions, container secrets, terminal streams, and audit records. Trust boundaries are Browser→Server and Server→Gateway→Engine. Availability attacks against Docker itself are outside V1's protection.
