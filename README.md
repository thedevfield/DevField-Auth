# DevField Auth — Phase 2-A / Phase 2-B

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
| BFF | `POST /internal/auth/oauth-intents` | `201` one-use provider start URL |
| Browser | `GET /oauth2/authorization/{provider}` | Provider redirect after one-use Intent claim |
| Provider | `GET /login/oauth2/code/{provider}` | Web callback handoff redirect |
| BFF | `POST /internal/auth/oauth-handoffs/exchange` | `200` opaque handle and User ID |

The BFF calls Auth on the server and places only the opaque handle in its host-only HttpOnly web cookie. Auth never sets a browser JWT cookie. OAuth callback creates a short-lived handoff; User, SocialIdentity, and AuthSession are committed only on BFF exchange. The Project/Interview integrations are later phases.

## Local setup

1. Start only the existing RepoQ local PostgreSQL Compose project if it is not running. Do not delete its volume.
2. Run `scripts/init-local-auth.ps1` once. It creates a fresh RSA pair and independent service credentials under ignored `.local/`. It refuses to replace existing keys.
3. In the PowerShell process for Auth, dot-source `../RepoQ/scripts/use-java21.ps1`, `../RepoQ/scripts/load-local-env.ps1`, and `.local/auth-local.ps1` in that order. The RepoQ script supplies `AUTH_DB_PASSWORD`.
4. Provide an SMTP server at `AUTH_SMTP_HOST:AUTH_SMTP_PORT`, such as the independent RepoQ Mailpit Compose. The verification link is `${AUTH_WEB_VERIFY_URL}#token=<proof>` and the Web route removes the fragment before calling the BFF. Never put the proof in an Auth URL query.
5. Run `./gradlew.bat bootRun`. Flyway applies `V1` through `V4` to `auth` on startup. Check `GET http://127.0.0.1:18080/actuator/health`.
6. Stop the Auth process with Ctrl+C. Leave other projects' containers and volumes untouched.

`./gradlew.bat test` uses a disposable Testcontainers PostgreSQL database, generated test RSA key, and fake mail sender. `./gradlew.bat build` runs the tests and builds the JAR. Docker must be available for integration tests. No test clears the development DB.

For Phase 2-B local Web integration, source an ignored OAuth/local override after `.local/auth-local.ps1`. Set SMTP to `127.0.0.1:11025`, the verification URL to `http://localhost:13000/verify-email`, Auth browser origin to `http://127.0.0.1:18080`, and Web OAuth callback to `http://localhost:13000/auth/oauth/callback`. Generate a fresh random 32-byte base64 `AUTH_OAUTH_CONTEXT_KEY` locally. Register the exact Provider callback `http://127.0.0.1:18080/login/oauth2/code/{provider}` in each Provider console, if that Provider permits loopback HTTP. Google, GitHub, and Kakao each require their own environment-only Client ID and Secret; a missing pair leaves that provider disabled while email Auth remains available. Never reuse PoC secrets. Provider console setup and real Provider E2E remain external tasks.

OAuth Intent creation has a PostgreSQL-backed global quota: `AUTH_OAUTH_START_WINDOW` (default `PT1M`), `AUTH_OAUTH_MAX_STARTS_PER_WINDOW` (default `120`), and `AUTH_OAUTH_MAX_ACTIVE_INTENTS` (default `600`). Excess starts return `429` without inserting an Intent. A fixed transaction-scoped advisory lock makes the check and insert atomic across Auth instances; it deliberately does not trust caller-supplied flow IDs, bindings, or forwarded IP headers. The quota is shared by all users, so an abusive caller can temporarily deny legitimate starts. Tune it against observed traffic and add a trusted ingress identity or edge protection for production. The lock serializes OAuth start writes, and both count queries use indexes; monitor lock wait and request latency.

`AUTH_OAUTH_CLEANUP_INTERVAL_MS` (default `30000`) and `AUTH_OAUTH_CLEANUP_BATCH_SIZE` (default `100`, maximum `1000`) control scheduled cleanup. Each run deletes up to one batch of expired or consumed `WEB_HANDOFF` rows, then up to one batch of expired `OAUTH_INTENT_LOGIN` rows without children. `FOR UPDATE SKIP LOCKED` avoids deleting proofs in an active exchange; callback parent reads hold a key-share lock until Handoff insertion commits. A parent remains until its Handoff is gone, including when the Handoff outlives the Intent. Repeated runs drain a backlog; monitor remaining expired OAuth rows if growth exceeds the cleanup rate. `VERIFY_SIGNUP`, users, credentials, identities, and sessions are outside this cleanup.

## Environment and credentials

`.env.example` lists every required variable. Service requests use `X-DevField-Service` (`bff`, `project`, or `interview`) and `X-DevField-Service-Key` (the corresponding raw key). Auth stores only their SHA-256 hashes in process environment variables. The raw local client keys are in ignored `.local/client-keys.ps1`. `X-DevField-Session-Handle` carries the opaque handle from BFF to Auth for AUTH-04/14. AUTH-15 uses the separate `Authorization: Bearer <user-jwt>` header plus the caller's service credential. These header names and key format are **Phase 2-A local choices**, pending a production service authentication decision. Production requires TLS, managed secrets, credential rotation, and network controls; the loopback HTTP setup is local only.

The local `AUTH_ISSUER`, `AUTH_AUDIENCE`, JWT/session/proof lifetimes, email normalization (trim and lowercase; no provider-specific alias folding), and in-memory per-email signup/login attempt limit are development choices, not production policy. The limiter is process-local and resets on restart, so production needs a shared abuse-control decision. RSA key files are loaded at startup, remain stable across restarts, and are not committed. Production needs managed key custody, old/new JWKS overlap, rotation, and cache policy. Missing required settings prevent startup.

Signup sends mail while its DB transaction is open: an SMTP failure rolls back the reservation and token. A delivered mail followed by a rare DB commit failure may leave an unusable link; a later retry replaces the reservation proof. Reliable delivery with an outbox is a later operational decision.

## Later phases

Phase 2-C: Project/Interview JWKS validation, AUTH-15 fail-closed check, and local resource ownership checks. Password reset, explicit social links, and coordinated account deletion remain outside Phase 2-B.
