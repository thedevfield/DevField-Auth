# DevField Auth — Phase 2-A

Java 21 / Spring Boot 4.0.9 service owning only the PostgreSQL `auth` schema. The API contract is in the DevField-Platform repository (`docs/contracts/auth/api-spec.md`).

## Implemented APIs

| Caller | Method and path | Success |
|---|---|---|
| BFF | `POST /api/auth/signup` | `202` verification required |
| BFF | `POST /api/auth/verify-email` | `204` |
| BFF | `POST /api/auth/login` | `200` opaque session handle and User ID |
| BFF | `POST /api/auth/logout` | `204` |
| Public | `GET /api/auth/jwks` | `200` public RSA keys |
| BFF | `POST /internal/auth/session-token` | `200` short-lived JWT, `Cache-Control: no-store` |
| Project/Interview | `POST /internal/auth/session-check` | `204` active user and session |

The BFF calls Auth on the server and places only the opaque handle in its host-only HttpOnly web cookie. Auth never sets a browser JWT cookie. The Web and Project integrations are later phases.

## Local setup

1. Start only the existing RepoQ local PostgreSQL Compose project if it is not running. Do not delete its volume.
2. Run `scripts/init-local-auth.ps1` once. It creates a fresh RSA pair and independent service credentials under ignored `.local/`. It refuses to replace existing keys.
3. In the PowerShell process for Auth, dot-source `../RepoQ/scripts/use-java21.ps1`, `../RepoQ/scripts/load-local-env.ps1`, and `.local/auth-local.ps1` in that order. The RepoQ script supplies `AUTH_DB_PASSWORD`.
4. Provide an SMTP server at `AUTH_SMTP_HOST:AUTH_SMTP_PORT`, such as a local Mailpit instance. The Auth repository does not create or alter Mailpit. The verification link is `${AUTH_WEB_VERIFY_URL}#token=<proof>`; Phase 2-B will implement that Web route. For manual local verification, read the test mail in the local inbox and POST its proof through the BFF or an HTTP client using BFF service credentials. Never put the proof in an Auth URL query.
5. Run `./gradlew.bat bootRun`. Flyway applies `V1` and `V2` to `auth` on startup. Check `GET http://127.0.0.1:18080/actuator/health`.
6. Stop the Auth process with Ctrl+C. Leave other projects' containers and volumes untouched.

`./gradlew.bat test` uses a disposable Testcontainers PostgreSQL database, generated test RSA key, and fake mail sender. `./gradlew.bat build` runs the tests and builds the JAR. Docker must be available for integration tests. No test clears the development DB.

## Environment and credentials

`.env.example` lists every required variable. Service requests use `X-DevField-Service` (`bff`, `project`, or `interview`) and `X-DevField-Service-Key` (the corresponding raw key). Auth stores only their SHA-256 hashes in process environment variables. The raw local client keys are in ignored `.local/client-keys.ps1`. `X-DevField-Session-Handle` carries the opaque handle from BFF to Auth for AUTH-04/14. AUTH-15 uses the separate `Authorization: Bearer <user-jwt>` header plus the caller's service credential. These header names and key format are **Phase 2-A local choices**, pending a production service authentication decision. Production requires TLS, managed secrets, credential rotation, and network controls; the loopback HTTP setup is local only.

The local `AUTH_ISSUER`, `AUTH_AUDIENCE`, JWT/session/proof lifetimes, email normalization (trim and lowercase; no provider-specific alias folding), and in-memory per-email signup/login attempt limit are development choices, not production policy. The limiter is process-local and resets on restart, so production needs a shared abuse-control decision. RSA key files are loaded at startup, remain stable across restarts, and are not committed. Production needs managed key custody, old/new JWKS overlap, rotation, and cache policy. Missing required settings prevent startup.

Signup sends mail while its DB transaction is open: an SMTP failure rolls back the reservation and token. A delivered mail followed by a rare DB commit failure may leave an unusable link; a later retry replaces the reservation proof. Reliable delivery with an outbox is a later operational decision.

## Later phases

Phase 2-B: Web same-origin session cookie, CSRF/Origin checks, verification UI, server-only JWT requests, and cookie deletion. Phase 2-C: Project/Interview JWKS validation, AUTH-15 fail-closed check, and local resource ownership checks. OAuth, email-login addition, password reset, social links, and coordinated account deletion are outside Phase 2-A.
