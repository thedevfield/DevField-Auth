# DevField Auth

Phase 1 Spring Boot 4.x / Java 21 service scaffold. Health and database ownership only; no authentication API is implemented.

## Local run

Start the separate development PostgreSQL from the sibling RepoQ directory. In the current PowerShell process, dot-source ..\RepoQ\scripts\use-java21.ps1 and ..\RepoQ\scripts\load-local-env.ps1. Use the Gradle wrapper:

1. .\gradlew.bat build
2. .\gradlew.bat bootRun
3. GET http://localhost:18080/actuator/health

Stop the application with Ctrl+C. Stop only the local Compose project from the sibling RepoQ directory with docker compose --env-file .env.local -f compose.local.yaml down when development ends. The auth service uses only the auth PostgreSQL schema. Do not commit passwords, private keys or local environment files. The health endpoint is public; other application routes are denied in Phase 1.
