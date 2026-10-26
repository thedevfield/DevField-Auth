package dev.devfield.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.doThrow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.devfield.auth.mail.VerificationMailer;
import dev.devfield.auth.util.Secrets;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataAccessException;
import org.springframework.mail.MailSendException;
import org.flywaydb.core.Flyway;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthIntegrationTest {
    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:17.6-alpine")
            .withDatabaseName("auth_test").withUsername("devfield_auth").withPassword("isolated-test-only-password");
    private static final KeyPair KEY;
    private static final Path PRIVATE;
    private static final Path PUBLIC;
    private static final String BFF = "test-bff-credential-with-sufficient-entropy-00001";
    private static final String PROJECT = "test-project-credential-with-sufficient-entropy-00002";
    private static final String INTERVIEW = "test-interview-credential-with-sufficient-entropy-00003";
    static {
        try {
            PG.start();
            try (Connection connection = DriverManager.getConnection(PG.getJdbcUrl(), PG.getUsername(), PG.getPassword());
                 var statement = connection.createStatement()) { statement.execute("CREATE SCHEMA auth AUTHORIZATION devfield_auth"); }
            var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
            KEY = generator.generateKeyPair();
            Path dir = Files.createTempDirectory("devfield-auth-test-key-");
            PRIVATE = dir.resolve("private.pem"); PUBLIC = dir.resolve("public.pem");
            Files.writeString(PRIVATE, pem("PRIVATE KEY", KEY.getPrivate().getEncoded()));
            Files.writeString(PUBLIC, pem("PUBLIC KEY", KEY.getPublic().getEncoded()));
            PRIVATE.toFile().deleteOnExit(); PUBLIC.toFile().deleteOnExit(); dir.toFile().deleteOnExit();
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }

    private static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry props) {
        props.add("spring.datasource.url", PG::getJdbcUrl);
        props.add("spring.datasource.username", PG::getUsername);
        props.add("spring.datasource.password", PG::getPassword);
        props.add("spring.mail.host", () -> "127.0.0.1");
        props.add("devfield.auth.issuer", () -> "https://auth.test.local");
        props.add("devfield.auth.audience", () -> "devfield-user-api-test");
        props.add("devfield.auth.private-key-path", PRIVATE::toString);
        props.add("devfield.auth.public-key-path", PUBLIC::toString);
        props.add("devfield.auth.web-verify-url", () -> "http://127.0.0.1:13000/verify");
        props.add("devfield.auth.mail-from", () -> "test@example.test");
        props.add("devfield.auth.service-keys.bff", () -> Secrets.sha256(BFF));
        props.add("devfield.auth.service-keys.project", () -> Secrets.sha256(PROJECT));
        props.add("devfield.auth.service-keys.interview", () -> Secrets.sha256(INTERVIEW));
    }

    @Value("${local.server.port}") int port;
    @Autowired JdbcTemplate db;
    @Autowired Flyway flyway;
    private final ObjectMapper json = new ObjectMapper();
    @MockitoBean VerificationMailer mailer;
    private final HttpClient http = HttpClient.newHttpClient();
    private final AtomicReference<String> proof = new AtomicReference<>();

    @BeforeEach void captureMail() {
        reset(mailer); proof.set(null);
        doAnswer(invocation -> { proof.set(invocation.getArgument(1)); return null; })
                .when(mailer).send(anyString(), anyString());
    }

    private HttpResponse<String> call(String method, String path, String body, String service, String key,
                                      String handle, String bearer) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
        if (service != null) builder.header("X-DevField-Service", service).header("X-DevField-Service-Key", key);
        if (handle != null) builder.header("X-DevField-Session-Handle", handle);
        if (bearer != null) builder.header("Authorization", "Bearer " + bearer);
        if (body != null) builder.header("Content-Type", "application/json");
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> bff(String method, String path, String body, String handle) throws Exception {
        return call(method, path, body, "bff", BFF, handle, null);
    }

    private String signup(String email) throws Exception {
        var response = bff("POST", "/api/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Test User\"}", null);
        assertEquals(202, response.statusCode(), response.body());
        assertEquals("verification_required", json.readTree(response.body()).get("status").asText());
        assertNotNull(proof.get());
        return proof.get();
    }

    private JsonNode verifiedLogin(String email) throws Exception {
        String token = signup(email);
        assertEquals(204, bff("POST", "/api/auth/verify-email", "{\"token\":\"" + token + "\"}", null).statusCode());
        var response = bff("POST", "/api/auth/login", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\"}", null);
        assertEquals(200, response.statusCode(), response.body());
        return json.readTree(response.body());
    }

    @Test void migrationAndEmailLifecycle() throws Exception {
        assertEquals(2, db.queryForObject("SELECT count(*) FROM auth.flyway_schema_history WHERE success", Integer.class));
        assertEquals(0, flyway.migrate().migrationsExecuted);
        String email = UUID.randomUUID() + "@example.test";
        String token = signup(email);
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.devfield_user u JOIN auth.email_credential c ON u.id=c.user_id WHERE c.normalized_email=?", Integer.class, email));
        assertEquals(403, bff("POST", "/api/auth/login", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\"}", null).statusCode());
        assertEquals(204, bff("POST", "/api/auth/verify-email", "{\"token\":\"" + token + "\"}", null).statusCode());
        assertEquals(410, bff("POST", "/api/auth/verify-email", "{\"token\":\"" + token + "\"}", null).statusCode());
        assertEquals(410, bff("POST", "/api/auth/verify-email", "{\"token\":\"" + Secrets.randomToken() + "\"}", null).statusCode());
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.devfield_user u JOIN auth.email_credential c ON u.id=c.user_id WHERE c.normalized_email=?", Integer.class, email));
        String hash = db.queryForObject("SELECT password_hash FROM auth.email_credential WHERE normalized_email=?", String.class, email);
        assertNotEquals("safe-test-password-123", hash);
        assertTrue(hash.startsWith("$2"));
        assertEquals(401, bff("POST", "/api/auth/login", "{\"email\":\"" + email + "\",\"password\":\"wrong\"}", null).statusCode());
        assertEquals(202, bff("POST", "/api/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Test\"}", null).statusCode());
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE normalized_email=?", Integer.class, email));
    }

    @Test void sessionJwtJwksAndLogout() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        JsonNode login = verifiedLogin(email);
        String handle = login.get("sessionHandle").asText();
        String userId = login.get("userId").asText();
        var secondLogin = bff("POST", "/api/auth/login", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\"}", null);
        assertEquals(200, secondLogin.statusCode());
        assertEquals(userId, json.readTree(secondLogin.body()).get("userId").asText());
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE session_handle_hash=?", Integer.class, handle));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE session_handle_hash=?", Integer.class, Secrets.sha256(handle)));
        assertEquals(401, bff("POST", "/internal/auth/session-token", null, Secrets.randomToken()).statusCode());
        var issued = bff("POST", "/internal/auth/session-token", null, handle);
        assertEquals(200, issued.statusCode());
        assertTrue(issued.headers().firstValue("cache-control").orElse("").contains("no-store"));
        String jwtValue = json.readTree(issued.body()).get("accessToken").asText();
        SignedJWT jwt = SignedJWT.parse(jwtValue);
        assertEquals("RS256", jwt.getHeader().getAlgorithm().getName());
        assertEquals(userId, jwt.getJWTClaimsSet().getSubject());
        assertNotNull(jwt.getJWTClaimsSet().getStringClaim("sid"));
        assertNotNull(jwt.getJWTClaimsSet().getJWTID());
        var jwks = call("GET", "/api/auth/jwks", null, null, null, null, null);
        assertEquals(200, jwks.statusCode());
        assertFalse(jwks.body().contains("\"d\""));
        RSAKey publicKey = (RSAKey) JWKSet.parse(jwks.body()).getKeys().getFirst();
        assertEquals(jwt.getHeader().getKeyID(), publicKey.getKeyID());
        assertTrue(jwt.verify(new RSASSAVerifier(publicKey.toRSAPublicKey())));
        assertEquals(204, call("POST", "/internal/auth/session-check", null, "project", PROJECT, null, jwtValue).statusCode());
        assertEquals(204, call("POST", "/internal/auth/session-check", null, "interview", INTERVIEW, null, jwtValue).statusCode());
        assertEquals(204, bff("POST", "/api/auth/logout", null, handle).statusCode());
        assertEquals(204, bff("POST", "/api/auth/logout", null, handle).statusCode());
        assertEquals(401, bff("POST", "/internal/auth/session-token", null, handle).statusCode());
        assertEquals(401, call("POST", "/internal/auth/session-check", null, "project", PROJECT, null, jwtValue).statusCode());
    }

    @Test void serviceAuthorizationAndHealth() throws Exception {
        assertEquals(200, call("GET", "/actuator/health", null, null, null, null, null).statusCode());
        assertEquals(401, call("POST", "/api/auth/signup", "{}", null, null, null, null).statusCode());
        assertEquals(403, call("POST", "/api/auth/signup", "{}", "project", PROJECT, null, null).statusCode());
        assertEquals(403, call("POST", "/internal/auth/session-check", null, "bff", BFF, null, "invalid").statusCode());
        assertEquals(401, call("POST", "/internal/auth/session-check", null, "project", "incorrect-service-credential-0000000000000", null, "invalid").statusCode());
        assertEquals(401, call("POST", "/internal/auth/session-check", null, null, null, null, "invalid").statusCode());
        assertEquals(403, call("POST", "/api/auth/poc/deleting", null, "bff", BFF, null, null).statusCode());
    }

    @Test void expiredProofAndReservationCanBeReused() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        String token = signup(email);
        db.update("UPDATE auth.action_token SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 second' WHERE token_hash=?", Secrets.sha256(token));
        assertEquals(410, bff("POST", "/api/auth/verify-email", "{\"token\":\"" + token + "\"}", null).statusCode());
        db.update("UPDATE auth.email_credential SET reservation_expires_at=now()-interval '1 second' WHERE normalized_email=?", email);
        assertEquals(202, bff("POST", "/api/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Retry\"}", null).statusCode());
        assertNotEquals(token, proof.get());
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE normalized_email=?", Integer.class, email));
    }

    @Test void tamperedClaimsAndExpiredSessionAreDenied() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        JsonNode login = verifiedLogin(email);
        String handle = login.get("sessionHandle").asText();
        String original = json.readTree(bff("POST", "/internal/auth/session-token", null, handle).body()).get("accessToken").asText();
        SignedJWT parsed = SignedJWT.parse(original);
        assertEquals(401, check(forge(parsed, "issuer", "https://wrong.example")));
        assertEquals(401, check(forge(parsed, "audience", "wrong")));
        assertEquals(401, check(forge(parsed, "expiration", "expired")));
        assertEquals(401, check(forge(parsed, "sid", UUID.randomUUID().toString())));
        assertEquals(401, check(forge(parsed, "subject", UUID.randomUUID().toString())));
        assertEquals(401, check(forge(parsed, "notBefore", "future")));
        var otherGenerator = KeyPairGenerator.getInstance("RSA"); otherGenerator.initialize(2048);
        var wrongKey = otherGenerator.generateKeyPair();
        SignedJWT wrongSignature = new SignedJWT(parsed.getHeader(), parsed.getJWTClaimsSet());
        wrongSignature.sign(new RSASSASigner(wrongKey.getPrivate()));
        assertEquals(401, check(wrongSignature.serialize()));
        SignedJWT wrongAlgorithm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .keyID(parsed.getHeader().getKeyID()).type(com.nimbusds.jose.JOSEObjectType.JWT).build(), parsed.getJWTClaimsSet());
        wrongAlgorithm.sign(new MACSigner(new byte[32]));
        assertEquals(401, check(wrongAlgorithm.serialize()));
        db.update("UPDATE auth.auth_session SET created_at=now()-interval '2 days',expires_at=now()-interval '1 second' WHERE session_handle_hash=?", Secrets.sha256(handle));
        assertEquals(401, check(original));
        assertEquals(401, bff("POST", "/internal/auth/session-token", null, handle).statusCode());
    }

    @Test void concurrentVerificationHasExactlyOneWinner() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        String token = signup(email);
        String body = "{\"token\":\"" + token + "\"}";
        try (var pool = Executors.newFixedThreadPool(2)) {
            Future<Integer> a = pool.submit(() -> bff("POST", "/api/auth/verify-email", body, null).statusCode());
            Future<Integer> b = pool.submit(() -> bff("POST", "/api/auth/verify-email", body, null).statusCode());
            assertEquals(java.util.Set.of(204, 410), java.util.Set.of(a.get(), b.get()));
        }
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.devfield_user u JOIN auth.email_credential c ON u.id=c.user_id WHERE c.normalized_email=?", Integer.class, email));
    }

    @Test void mailFailureRollsBackReservation() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        doThrow(new MailSendException("test failure")).when(mailer).send(anyString(), anyString());
        var response = bff("POST", "/api/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Test\"}", null);
        assertEquals(503, response.statusCode());
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE normalized_email=?", Integer.class, email));
    }

    @Test void accountStateAndOtherSessionStayIsolated() throws Exception {
        JsonNode first = verifiedLogin(UUID.randomUUID() + "@example.test");
        JsonNode second = verifiedLogin(UUID.randomUUID() + "@example.test");
        String firstHandle = first.get("sessionHandle").asText();
        String secondHandle = second.get("sessionHandle").asText();
        String firstJwt = json.readTree(bff("POST", "/internal/auth/session-token", null, firstHandle).body()).get("accessToken").asText();
        String secondJwt = json.readTree(bff("POST", "/internal/auth/session-token", null, secondHandle).body()).get("accessToken").asText();
        assertEquals(204, bff("POST", "/api/auth/logout", null, firstHandle).statusCode());
        assertEquals(401, check(firstJwt));
        assertEquals(204, check(secondJwt));
        db.update("UPDATE auth.devfield_user SET state='DELETING',updated_at=now() WHERE id=?", UUID.fromString(second.get("userId").asText()));
        assertEquals(403, check(secondJwt));
        assertEquals(403, bff("POST", "/internal/auth/session-token", null, secondHandle).statusCode());
    }

    @Test void databaseUniquenessAndSignupCooldown() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        String firstProof = signup(email);
        assertEquals(202, bff("POST", "/api/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Test\"}", null).statusCode());
        assertEquals(firstProof, proof.get());
        assertThrows(DataAccessException.class, () -> db.update("INSERT INTO auth.email_credential(id,normalized_email,password_hash,reservation_expires_at) VALUES (?,?,?,now()+interval '1 hour')",
                UUID.randomUUID(), email, "$2a$12$abcdefghijklmnopqrstuvwxyz1234567890ABCDE"));
        assertThrows(DataAccessException.class, () -> db.update("INSERT INTO auth.action_token(id,email_credential_id,purpose,token_hash,expires_at) SELECT ?,id,'VERIFY_SIGNUP',?,now()+interval '1 hour' FROM auth.email_credential WHERE normalized_email=?",
                UUID.randomUUID(), Secrets.sha256(firstProof), email));
        UUID fakeUser = UUID.randomUUID();
        assertThrows(DataAccessException.class, () -> db.update("UPDATE auth.email_credential SET user_id=?,verified_at=now(),reservation_expires_at=NULL WHERE normalized_email=?", fakeUser, email));
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String existingHash = Secrets.sha256(login.get("sessionHandle").asText());
        UUID actualUser = UUID.fromString(login.get("userId").asText());
        assertThrows(DataAccessException.class, () -> db.update("INSERT INTO auth.auth_session(id,user_id,session_handle_hash,expires_at) VALUES (?,?,?,now()+interval '1 hour')",
                UUID.randomUUID(), actualUser, existingHash));
    }

    @Test void concurrentSignupKeepsOneReservation() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        String body = "{\"email\":\"" + email + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Concurrent\"}";
        try (var pool = Executors.newFixedThreadPool(2)) {
            Future<Integer> a = pool.submit(() -> bff("POST", "/api/auth/signup", body, null).statusCode());
            Future<Integer> b = pool.submit(() -> bff("POST", "/api/auth/signup", body, null).statusCode());
            assertEquals(202, a.get());
            assertEquals(202, b.get());
        }
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE normalized_email=?", Integer.class, email));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.action_token t JOIN auth.email_credential c ON c.id=t.email_credential_id WHERE c.normalized_email=?", Integer.class, email));
    }

    @Test void signupAndLoginRateLimit() throws Exception {
        String signupEmail = UUID.randomUUID() + "@example.test";
        String signupBody = "{\"email\":\"" + signupEmail + "\",\"password\":\"safe-test-password-123\",\"displayName\":\"Test\"}";
        for (int i = 0; i < 5; i++) assertEquals(202, bff("POST", "/api/auth/signup", signupBody, null).statusCode());
        assertEquals(429, bff("POST", "/api/auth/signup", signupBody, null).statusCode());
        String loginEmail = UUID.randomUUID() + "@example.test";
        String loginBody = "{\"email\":\"" + loginEmail + "\",\"password\":\"wrong\"}";
        for (int i = 0; i < 5; i++) assertEquals(401, bff("POST", "/api/auth/login", loginBody, null).statusCode());
        assertEquals(429, bff("POST", "/api/auth/login", loginBody, null).statusCode());
    }

    @Test void authDatabaseFailureReturns503() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        String jwt = json.readTree(bff("POST", "/internal/auth/session-token", null, handle).body()).get("accessToken").asText();
        db.execute("ALTER TABLE auth.auth_session RENAME TO auth_session_temporarily_unavailable");
        try { assertEquals(503, check(jwt)); }
        finally { db.execute("ALTER TABLE auth.auth_session_temporarily_unavailable RENAME TO auth_session"); }
    }

    private int check(String token) throws Exception {
        return call("POST", "/internal/auth/session-check", null, "project", PROJECT, null, token).statusCode();
    }

    private String forge(SignedJWT original, String change, String value) throws Exception {
        var builder = new JWTClaimsSet.Builder(original.getJWTClaimsSet());
        switch (change) {
            case "issuer" -> builder.issuer(value);
            case "audience" -> builder.audience(value);
            case "expiration" -> builder.expirationTime(Date.from(Instant.now().minusSeconds(1)));
            case "sid" -> builder.claim("sid", value);
            case "subject" -> builder.subject(value);
            case "notBefore" -> builder.notBeforeTime(Date.from(Instant.now().plusSeconds(60)));
            default -> throw new IllegalArgumentException();
        }
        SignedJWT forged = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(original.getHeader().getKeyID()).type(com.nimbusds.jose.JOSEObjectType.JWT).build(), builder.build());
        forged.sign(new RSASSASigner(KEY.getPrivate()));
        return forged.serialize();
    }
}
