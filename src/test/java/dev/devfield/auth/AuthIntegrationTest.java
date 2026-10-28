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
import dev.devfield.auth.oauth.OAuthFlowStore;
import dev.devfield.auth.oauth.GoogleReauthPolicy;
import dev.devfield.auth.oauth.OAuthIntentResolver;
import dev.devfield.auth.oauth.OAuthResultHandlers;
import dev.devfield.auth.account.AccountChanges;
import dev.devfield.auth.oauth.OAuthProviders;
import dev.devfield.auth.oauth.OAuthStartValidationFilter;
import dev.devfield.auth.util.Secrets;
import java.io.IOException;
import java.net.URI;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.dao.DataAccessException;
import org.springframework.mail.MailSendException;
import org.flywaydb.core.Flyway;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.testcontainers.containers.PostgreSQLContainer;
import com.sun.net.httpserver.HttpServer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(AuthIntegrationTest.MockProviderConfiguration.class)
class AuthIntegrationTest {
    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>("postgres:17.6-alpine")
            .withDatabaseName("auth_test").withUsername("devfield_auth").withPassword("isolated-test-only-password");
    private static final KeyPair KEY;
    private static final Path PRIVATE;
    private static final Path PUBLIC;
    private static final String BFF = "test-bff-credential-with-sufficient-entropy-00001";
    private static final String PROJECT = "test-project-credential-with-sufficient-entropy-00002";
    private static final String INTERVIEW = "test-interview-credential-with-sufficient-entropy-00003";
    private static final HttpServer MOCK_PROVIDER;
    private static final AtomicReference<String> GOOGLE_NONCE = new AtomicReference<>();
    private static final AtomicReference<String> GOOGLE_AUDIENCE = new AtomicReference<>("mock-google-client");
    private static final AtomicReference<String> GOOGLE_SUB = new AtomicReference<>("google-sub-654321");
    private static final AtomicReference<Long> GOOGLE_AUTH_TIME = new AtomicReference<>();
    private static final AtomicReference<String> MOCK_GITHUB_ID = new AtomicReference<>("654321");
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
            MOCK_PROVIDER = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            MOCK_PROVIDER.createContext("/token", exchange -> {
                String idToken = "";
                if (GOOGLE_NONCE.get() != null) {
                    try {
                        var builder = new JWTClaimsSet.Builder()
                                .issuer("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort())
                                .audience(GOOGLE_AUDIENCE.get()).subject(GOOGLE_SUB.get())
                                .issueTime(Date.from(Instant.now())).expirationTime(Date.from(Instant.now().plusSeconds(300)))
                                .claim("nonce", GOOGLE_NONCE.get());
                        if (GOOGLE_AUTH_TIME.get() != null) builder.claim("auth_time", GOOGLE_AUTH_TIME.get());
                        var claims = builder.build();
                        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("mock-google-key").build(), claims);
                        signed.sign(new RSASSASigner(KEY.getPrivate()));
                        idToken = ",\"id_token\":\"" + signed.serialize() + "\"";
                    } catch (Exception e) { throw new IOException(e); }
                }
                byte[] body = ("{\"access_token\":\"mock-access-token\",\"token_type\":\"Bearer\",\"expires_in\":300" + idToken + "}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
            });
            MOCK_PROVIDER.createContext("/user", exchange -> {
                byte[] body = ("{\"id\":\"" + MOCK_GITHUB_ID.get() + "\",\"login\":\"mock-account\"}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
            });
            MOCK_PROVIDER.createContext("/userinfo", exchange -> {
                byte[] body = ("{\"sub\":\"" + GOOGLE_SUB.get() + "\"}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
            });
            MOCK_PROVIDER.createContext("/jwks", exchange -> {
                String jwks = new JWKSet(new RSAKey.Builder((RSAPublicKey) KEY.getPublic())
                        .keyID("mock-google-key").build()).toPublicJWKSet().toString();
                byte[] body = jwks.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); }
            });
            MOCK_PROVIDER.start();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> MOCK_PROVIDER.stop(0)));
        } catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }

    @TestConfiguration
    static class MockProviderConfiguration {
        @Bean @Primary OAuthProviders mockProviders() {
            return new OAuthProviders("", "", "", "", "", "", "http://127.0.0.1:18080") {
                private final ClientRegistration google = ClientRegistration.withRegistrationId("google")
                        .clientId("mock-google-client").clientSecret("mock-google-secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("http://127.0.0.1:18080/login/oauth2/code/google").scope("openid")
                        .authorizationUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/authorize")
                        .tokenUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/token")
                        .jwkSetUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/jwks")
                        .issuerUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort())
                        .userInfoUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/userinfo")
                        .userNameAttributeName("sub").clientName("Mock Google").build();
                private final ClientRegistration github = ClientRegistration.withRegistrationId("github")
                        .clientId("mock-client").clientSecret("mock-secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("http://127.0.0.1:18080/login/oauth2/code/github")
                        .authorizationUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/authorize")
                        .tokenUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/token")
                        .userInfoUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/user")
                        .userNameAttributeName("id").clientName("Mock GitHub").build();
                private final ClientRegistration kakao = ClientRegistration.withRegistrationId("kakao")
                        .clientId("mock-kakao-client").clientSecret("mock-kakao-secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("http://127.0.0.1:18080/login/oauth2/code/kakao")
                        .authorizationUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/authorize")
                        .tokenUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/token")
                        .userInfoUri("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/user")
                        .userNameAttributeName("id").clientName("Mock Kakao").build();
                @Override public ClientRegistration findByRegistrationId(String id) {
                    return "google".equals(id) ? google : "github".equals(id) ? github : "kakao".equals(id) ? kakao : null;
                }
                @Override public boolean enabled(String provider) { return findByRegistrationId(provider) != null; }
                @Override public boolean anyEnabled() { return true; }
                @Override public java.util.Iterator<ClientRegistration> iterator() { return java.util.List.of(google, github, kakao).iterator(); }
            };
        }
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
        props.add("AUTH_OAUTH_CONTEXT_KEY", () -> Base64.getEncoder().encodeToString(new byte[32]));
        props.add("AUTH_GOOGLE_REAUTH_IDENTITY_ONLY_ENABLED", () -> "true");
        props.add("devfield.auth.oauth.cleanup-interval-ms", () -> "86400000");
    }

    @Value("${local.server.port}") int port;
    @Autowired JdbcTemplate db;
    @Autowired Flyway flyway;
    @Autowired OAuthFlowStore oauthFlows;
    @Autowired OAuthProviders oauthProviders;
    @Autowired OAuthResultHandlers oauthResults;
    @Autowired AccountChanges accountChanges;
    @Autowired PlatformTransactionManager transactions;
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

    private OAuthFlowStore.HandoffResult socialLogin(String provider, String providerId, String providerEmail) {
        String binding = Secrets.randomToken();
        String flow = Secrets.randomToken();
        boolean existing = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider=? AND provider_user_id=?", Integer.class, provider, providerId) > 0;
        String route = existing ? "LOGIN_COMPLETE" : "SIGNUP_COMPLETE";
        String url = oauthFlows.createIntent(provider, Secrets.sha256(binding), flow, route);
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), provider, state);
        String handoff = oauthFlows.createHandoff(state, provider, providerId, providerEmail);
        return oauthFlows.exchange(handoff, binding, flow, null, existing ? "LOGIN" : "SIGNUP");
    }

    private OAuthFlowStore.HandoffResult socialAttempt(String provider, String providerId, String route, String purpose) {
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        String url = oauthFlows.createIntent(provider, Secrets.sha256(binding), flow, route);
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), provider, state);
        String handoff = oauthFlows.createHandoff(state, provider, providerId, null);
        return oauthFlows.exchange(handoff, binding, flow, null, purpose);
    }

    @Test void socialLoginAndSignupNeverSwitchIntent() {
        String id = "intent-" + UUID.randomUUID();
        int before = db.queryForObject("SELECT count(*) FROM auth.devfield_user", Integer.class);
        var missing = socialAttempt("github", id, "LOGIN_COMPLETE", "LOGIN");
        assertEquals("SIGNUP_REQUIRED", missing.outcome());
        assertNull(missing.sessionHandle());
        assertNull(missing.userId());
        assertEquals(before, db.queryForObject("SELECT count(*) FROM auth.devfield_user", Integer.class));
        var created = socialAttempt("github", id, "SIGNUP_COMPLETE", "SIGNUP");
        assertEquals("SIGNED_UP", created.outcome());
        assertNotNull(created.sessionHandle());
        var duplicate = socialAttempt("github", id, "SIGNUP_COMPLETE", "SIGNUP");
        assertEquals("EXISTING_ACCOUNT", duplicate.outcome());
        assertNull(duplicate.sessionHandle());
        assertNull(duplicate.userId());
        assertEquals(before + 1, db.queryForObject("SELECT count(*) FROM auth.devfield_user", Integer.class));
        var relogin = socialAttempt("github", id, "LOGIN_COMPLETE", "LOGIN");
        assertEquals("LOGGED_IN", relogin.outcome());
        assertEquals(created.userId(), relogin.userId());
    }

    @Test void googleReauthIdentityOnlyOmitsClaimsAndStrictModeRequiresThem() throws Exception {
        var existing = socialLogin("google", "google-sub-654321", null);
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        String url = accountChanges.socialProofStart(existing.sessionHandle(), "google", Secrets.sha256(binding), flow);
        URI start = URI.create(url);
        var response = call("GET", start.getRawPath() + "?" + start.getRawQuery(), null, null, null, null, null);
        assertEquals(302, response.statusCode());
        URI authorize = URI.create(response.headers().firstValue("location").orElseThrow());
        assertFalse(authorize.getRawQuery().contains("claims="));

        String strictBinding = Secrets.randomToken(), strictFlow = Secrets.randomToken();
        String strictUrl = accountChanges.socialProofStart(existing.sessionHandle(), "google", Secrets.sha256(strictBinding), strictFlow);
        var strictRequest = new MockHttpServletRequest("GET", "/oauth2/authorization/google");
        strictRequest.setServletPath("/oauth2/authorization/google");
        strictRequest.setParameter("intent", URI.create(strictUrl).getRawQuery().substring("intent=".length()));
        var strict = new OAuthIntentResolver(oauthProviders, oauthFlows, new GoogleReauthPolicy(false)).resolve(strictRequest);
        JsonNode claims = json.readTree((String) strict.getAdditionalParameters().get("claims"));
        assertTrue(claims.path("id_token").path("auth_time").path("essential").asBoolean());
        assertEquals(1, claims.size());
        String strictEncoded = java.util.Arrays.stream(URI.create(strict.getAuthorizationRequestUri()).getRawQuery().split("&"))
                .filter(item -> item.startsWith("claims="))
                .map(item -> item.substring("claims=".length())).findFirst().orElseThrow();
        assertEquals(claims, json.readTree(URLDecoder.decode(strictEncoded, StandardCharsets.UTF_8)));
    }

    @Test void googleReauthIdentityOnlyAcceptsMissingAuthTimeAndRejectsDifferentSub() throws Exception {
        var existing = socialLogin("google", "google-sub-654321", null);
        int sessionsBefore = db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE user_id=?", Integer.class, existing.userId());
        for (String sub : new String[]{"google-sub-654321", "different-google-sub"}) {
            String binding = Secrets.randomToken(), flow = Secrets.randomToken();
            String url = accountChanges.socialProofStart(existing.sessionHandle(), "google", Secrets.sha256(binding), flow);
            URI start = URI.create(url);
            var response = call("GET", start.getRawPath() + "?" + start.getRawQuery(), null, null, null, null, null);
            assertEquals(302, response.statusCode());
            URI authorize = URI.create(response.headers().firstValue("location").orElseThrow());
            String state = java.util.Arrays.stream(authorize.getRawQuery().split("&"))
                    .filter(item -> item.startsWith("state="))
                    .map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8)).findFirst().orElseThrow();
            GOOGLE_NONCE.set(java.util.Arrays.stream(authorize.getRawQuery().split("&"))
                    .filter(item -> item.startsWith("nonce="))
                    .map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8)).findFirst().orElseThrow());
            GOOGLE_SUB.set(sub);
            GOOGLE_AUTH_TIME.set(null);
            HttpResponse<String> callback;
            try { callback = call("GET", "/login/oauth2/code/google?code=mock-code&state=" + state, null, null, null, null, null); }
            finally { GOOGLE_NONCE.set(null); GOOGLE_SUB.set("google-sub-654321"); }
            assertEquals(303, callback.statusCode());
            String location = callback.headers().firstValue("location").orElseThrow();
            assertTrue(location.contains("&purpose=REAUTH"), location);
            String handoff = java.util.Arrays.stream(URI.create(location).getRawFragment().split("&"))
                    .filter(item -> item.startsWith("handoff=")).map(item -> item.substring(8)).findFirst().orElseThrow();
            if (sub.equals("google-sub-654321")) {
                var exchanged = oauthFlows.exchange(handoff, binding, flow, existing.sessionHandle(), "ACCOUNT");
                assertEquals(existing.userId(), exchanged.userId());
                assertNull(exchanged.sessionHandle());
                assertNotNull(exchanged.reauthProof());
            } else assertEquals(403, assertThrows(dev.devfield.auth.api.ApiError.class,
                    () -> oauthFlows.exchange(handoff, binding, flow, existing.sessionHandle(), "ACCOUNT")).status().value());
        }
        assertEquals(sessionsBefore, db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE user_id=?", Integer.class, existing.userId()));
        assertEquals(200, bff("GET", "/api/account/me", null, existing.sessionHandle()).statusCode());
    }

    @Test void strictGoogleReauthRejectsMissingAndStaleAuthTime() throws Exception {
        var existing = socialLogin("google", "google-sub-654321", null);
        var strict = new OAuthResultHandlers(oauthFlows, "http://localhost:13000/auth/oauth/callback", new GoogleReauthPolicy(false));
        for (Long authTime : new Long[]{null, Instant.now().minusSeconds(601).getEpochSecond(), Instant.now().plusSeconds(60).getEpochSecond(), Instant.now().minusSeconds(2).getEpochSecond()}) {
            String binding = Secrets.randomToken(), flow = Secrets.randomToken();
            String url = accountChanges.socialProofStart(existing.sessionHandle(), "google", Secrets.sha256(binding), flow);
            String state = Secrets.randomToken();
            oauthFlows.claimStart(URI.create(url).getRawQuery().substring("intent=".length()), "google", state);
            var request = new MockHttpServletRequest("GET", "/login/oauth2/code/google");
            request.setParameter("state", state);
            var response = new MockHttpServletResponse();
            var claims = new java.util.HashMap<String, Object>();
            claims.put("sub", "google-sub-654321");
            if (authTime != null) claims.put("auth_time", authTime);
            var idToken = new org.springframework.security.oauth2.core.oidc.OidcIdToken("test-id-token", Instant.now(), Instant.now().plusSeconds(300), claims);
            var user = new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(java.util.List.of(), idToken);
            strict.onAuthenticationSuccess(request, response,
                    new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user, java.util.List.of(), "google"));
            String location = response.getHeader("Location");
            if (authTime == null) assertTrue(location.contains("#error=google_reauth_unavailable"));
            else if (authTime < Instant.now().minusSeconds(300).getEpochSecond() || authTime > Instant.now().getEpochSecond())
                assertTrue(location.contains("#error=google_reauth_stale"));
            else assertTrue(location.contains("&purpose=REAUTH"));
        }
    }

    @Test void googleIdentityOnlyStillRejectsInvalidIdTokenAndNonce() throws Exception {
        var existing = socialLogin("google", "google-sub-654321", null);
        for (String defect : new String[]{"audience", "nonce"}) {
            String binding = Secrets.randomToken(), flow = Secrets.randomToken();
            String url = accountChanges.socialProofStart(existing.sessionHandle(), "google", Secrets.sha256(binding), flow);
            URI start = URI.create(url);
            var started = call("GET", start.getRawPath() + "?" + start.getRawQuery(), null, null, null, null, null);
            assertEquals(302, started.statusCode());
            URI authorize = URI.create(started.headers().firstValue("location").orElseThrow());
            String state = java.util.Arrays.stream(authorize.getRawQuery().split("&"))
                    .filter(item -> item.startsWith("state="))
                    .map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8)).findFirst().orElseThrow();
            GOOGLE_NONCE.set("nonce".equals(defect) ? "wrong-nonce" : java.util.Arrays.stream(authorize.getRawQuery().split("&"))
                    .filter(item -> item.startsWith("nonce="))
                    .map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8)).findFirst().orElseThrow());
            GOOGLE_AUDIENCE.set("audience".equals(defect) ? "wrong-client" : "mock-google-client");
            HttpResponse<String> callback;
            try { callback = call("GET", "/login/oauth2/code/google?code=mock-code&state=" + state, null, null, null, null, null); }
            finally { GOOGLE_NONCE.set(null); GOOGLE_AUDIENCE.set("mock-google-client"); }
            assertEquals(303, callback.statusCode());
            assertTrue(callback.headers().firstValue("location").orElseThrow().contains("#error="));
            assertFalse(callback.headers().firstValue("location").orElseThrow().contains("handoff="));
        }
        assertEquals(200, bff("GET", "/api/account/me", null, existing.sessionHandle()).statusCode());
    }

    @Test void oauthFailureSeparatesAccessDeniedProviderErrorAndCallbackFailure() throws Exception {
        for (String providerError : new String[]{"access_denied", "invalid_request", ""}) {
            String flow = Secrets.randomToken(), binding = Secrets.randomToken();
            String url = oauthFlows.createIntent("google", Secrets.sha256(binding), flow, "LOGIN_COMPLETE");
            String state = Secrets.randomToken();
            oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "google", state);
            var request = new MockHttpServletRequest("GET", "/login/oauth2/code/google");
            request.setParameter("state", state);
            if (!providerError.isEmpty()) request.setParameter("error", providerError);
            var response = new MockHttpServletResponse();
            oauthResults.onAuthenticationFailure(request, response,
                    new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                            new org.springframework.security.oauth2.core.OAuth2Error(providerError.isEmpty() ? "invalid_token_response" : providerError)));
            String location = response.getHeader("Location");
            assertEquals(303, response.getStatus());
            assertTrue(location.contains("#error=" + (providerError.equals("access_denied") ? "oauth_cancelled"
                    : providerError.isEmpty() ? "oauth_callback_failed" : "oauth_provider_rejected")));
            assertTrue(location.contains("&flowId=" + flow));
            assertTrue(location.matches(".*&ref=[0-9a-f-]{36}$"));
            assertFalse(location.contains(state));
        }
    }

    @Test void accountLinkRequiresRecentProofAndKeepsSession() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        UUID user = UUID.fromString(login.get("userId").asText());
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        assertEquals(403, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> accountChanges.linkStart(handle, "github", Secrets.randomToken(), Secrets.sha256(binding), flow)).status().value());
        String proof = accountChanges.passwordProof(handle, "safe-test-password-123");
        String url = accountChanges.linkStart(handle, "github", proof, Secrets.sha256(binding), flow);
        assertEquals(403, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> accountChanges.linkStart(handle, "google", proof, Secrets.sha256(Secrets.randomToken()), Secrets.randomToken())).status().value());
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
        String providerId = "link-" + UUID.randomUUID();
        String handoff = oauthFlows.createHandoff(state, "github", providerId, null);
        assertEquals(400, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, binding, flow, handle, "LOGIN")).status().value());
        var linked = oauthFlows.exchange(handoff, binding, flow, handle, "ACCOUNT");
        assertEquals(user, linked.userId());
        assertNull(linked.sessionHandle());
        assertEquals("LINK_COMPLETE", linked.returnRoute());
        assertEquals(200, bff("GET", "/api/account/me", null, handle).statusCode());
        assertEquals(2, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=?", Integer.class, user)
                + db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL", Integer.class, user));
        assertEquals(410, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, binding, flow, handle, "ACCOUNT")).status().value());
        String otherHandle = socialLogin("github", providerId, null).sessionHandle();
        assertEquals(user, socialLogin("github", providerId, null).userId());
        String unlinkProof = accountChanges.passwordProof(handle, "safe-test-password-123");
        accountChanges.unlink(handle, "github", unlinkProof);
        assertEquals(401, bff("GET", "/api/account/me", null, otherHandle).statusCode());
        assertEquals(200, bff("GET", "/api/account/me", null, handle).statusCode());
        assertNotEquals(user, socialLogin("github", providerId, null).userId());
    }

    @Test void unregisteredMockProviderLinksToExistingUserWithoutReplacingSession() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        String userId = login.get("userId").asText();
        String providerId = "mock-link-" + UUID.randomUUID();
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        int sessionsBefore = db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE user_id=?", Integer.class, UUID.fromString(userId));
        String proof = accountChanges.passwordProof(handle, "safe-test-password-123");
        String url = accountChanges.linkStart(handle, "github", proof, Secrets.sha256(binding), flow);
        MOCK_GITHUB_ID.set(providerId);
        try {
            URI start = URI.create(url);
            var started = call("GET", start.getRawPath() + "?" + start.getRawQuery(), null, null, null, null, null);
            assertEquals(302, started.statusCode());
            URI authorize = URI.create(started.headers().firstValue("location").orElseThrow());
            String state = java.util.Arrays.stream(authorize.getRawQuery().split("&"))
                    .filter(item -> item.startsWith("state="))
                    .map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8)).findFirst().orElseThrow();
            var callback = call("GET", "/login/oauth2/code/github?code=mock-code&state=" + state, null, null, null, null, null);
            assertEquals(303, callback.statusCode());
            URI location = URI.create(callback.headers().firstValue("location").orElseThrow());
            assertTrue(location.getRawFragment().contains("&purpose=LINK"));
            String handoff = java.util.Arrays.stream(location.getRawFragment().split("&"))
                    .filter(item -> item.startsWith("handoff=")).map(item -> item.substring(8)).findFirst().orElseThrow();
            var exchanged = bff("POST", "/internal/auth/oauth-handoffs/exchange",
                    json.writeValueAsString(java.util.Map.of("handoff", handoff, "browserBinding", binding,
                            "flowId", flow, "expectedPurpose", "ACCOUNT")), handle);
            assertEquals(200, exchanged.statusCode(), exchanged.body());
            JsonNode result = json.readTree(exchanged.body());
            assertEquals("LINKED", result.get("outcome").asText());
            assertEquals(userId, result.get("userId").asText());
            assertTrue(result.path("sessionHandle").isNull());
            assertEquals(sessionsBefore, db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE user_id=?", Integer.class, UUID.fromString(userId)));
            assertEquals(200, bff("GET", "/api/account/me", null, handle).statusCode());
            assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider='github' AND provider_user_id=?",
                    Integer.class, UUID.fromString(userId), providerId));
        } finally { MOCK_GITHUB_ID.set("654321"); }
    }

    @Test void unlinkRejectsLastMethodAndRevokesOtherSessions() throws Exception {
        var social = socialLogin("github", "unlink-" + UUID.randomUUID(), null);
        String only = social.sessionHandle();
        String reauthBinding = Secrets.randomToken(), flow = Secrets.randomToken();
        String url = accountChanges.socialProofStart(only, "github", Secrets.sha256(reauthBinding), flow);
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
        String handoff = oauthFlows.createHandoff(state, "github", "wrong-provider-id", null);
        assertEquals(403, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, reauthBinding, flow, only, "ACCOUNT")).status().value());
        String correctId = db.queryForObject("SELECT provider_user_id FROM auth.social_identity WHERE user_id=? AND provider='github'", String.class, social.userId());
        String goodBinding = Secrets.randomToken(), goodFlow = Secrets.randomToken();
        String goodUrl = accountChanges.socialProofStart(only, "github", Secrets.sha256(goodBinding), goodFlow);
        String goodState = Secrets.randomToken();
        oauthFlows.claimStart(goodUrl.substring(goodUrl.indexOf("intent=") + 7), "github", goodState);
        String goodHandoff = oauthFlows.createHandoff(goodState, "github", correctId, null);
        String reauth = oauthFlows.exchange(goodHandoff, goodBinding, goodFlow, only, "ACCOUNT").reauthProof();
        assertEquals(409, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> accountChanges.unlink(only, "github", reauth)).status().value());
    }

    @Test void concurrentLastMethodUnlinkLeavesOneIdentity() throws Exception {
        var social = socialLogin("github", "parallel-" + UUID.randomUUID(), null);
        UUID user = social.userId();
        db.update("INSERT INTO auth.social_identity(id,user_id,provider,provider_user_id) VALUES (?,?,?,?)",
                UUID.randomUUID(), user, "google", "parallel-" + UUID.randomUUID());
        String first = Secrets.randomToken(), second = Secrets.randomToken();
        for (String proof : java.util.List.of(first, second))
            db.update("INSERT INTO auth.action_token(id,user_id,session_id,purpose,token_hash,expires_at) " +
                    "SELECT ?,?,s.id,'ACCOUNT_REAUTH',?,now()+interval '5 minutes' FROM auth.auth_session s " +
                    "WHERE s.session_handle_hash=?", UUID.randomUUID(), user, Secrets.sha256(proof), Secrets.sha256(social.sessionHandle()));
        var workers = Executors.newFixedThreadPool(2);
        var ready = new CountDownLatch(2);
        var go = new CountDownLatch(1);
        try {
            Future<Integer> a = workers.submit(() -> {
                ready.countDown(); go.await();
                try { accountChanges.unlink(social.sessionHandle(), "github", first); return 204; }
                catch (dev.devfield.auth.api.ApiError e) { return e.status().value(); }
            });
            Future<Integer> b = workers.submit(() -> {
                ready.countDown(); go.await();
                try { accountChanges.unlink(social.sessionHandle(), "google", second); return 204; }
                catch (dev.devfield.auth.api.ApiError e) { return e.status().value(); }
            });
            assertTrue(ready.await(5, TimeUnit.SECONDS)); go.countDown();
            assertEquals(java.util.Set.of(204, 409), java.util.Set.of(a.get(), b.get()));
            assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=?", Integer.class, user));
        } finally { workers.shutdownNow(); }
    }

    @Test void otherUsersProviderCannotBeLinkedOrMerged() throws Exception {
        var owner = socialLogin("github", "owned-" + UUID.randomUUID(), null);
        JsonNode email = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = email.get("sessionHandle").asText();
        String proof = accountChanges.passwordProof(handle, "safe-test-password-123");
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        String url = accountChanges.linkStart(handle, "github", proof, Secrets.sha256(binding), flow);
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
        String providerId = db.queryForObject("SELECT provider_user_id FROM auth.social_identity WHERE user_id=? AND provider='github'",
                String.class, owner.userId());
        String handoff = oauthFlows.createHandoff(state, "github", providerId, "same@example.test");
        assertEquals(409, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, binding, flow, handle, "ACCOUNT")).status().value());
        assertEquals(owner.userId(), db.queryForObject("SELECT user_id FROM auth.social_identity WHERE provider='github' AND provider_user_id=?", UUID.class, providerId));
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=?", Integer.class,
                UUID.fromString(email.get("userId").asText())));
    }

    @Test void accountLinkHandoffFailsAfterLogoutOrDeleting() throws Exception {
        for (boolean deleting : new boolean[]{false, true}) {
            JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
            String handle = login.get("sessionHandle").asText();
            UUID user = UUID.fromString(login.get("userId").asText());
            String proof = accountChanges.passwordProof(handle, "safe-test-password-123");
            String binding = Secrets.randomToken(), flow = Secrets.randomToken();
            String url = accountChanges.linkStart(handle, "github", proof, Secrets.sha256(binding), flow);
            String state = Secrets.randomToken();
            oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
            String providerId = "aborted-" + UUID.randomUUID();
            String handoff = oauthFlows.createHandoff(state, "github", providerId, null);
            if (deleting) db.update("UPDATE auth.devfield_user SET state='DELETING' WHERE id=?", user);
            else assertEquals(204, bff("POST", "/api/auth/logout", null, handle).statusCode());
            assertThrows(dev.devfield.auth.api.ApiError.class,
                    () -> oauthFlows.exchange(handoff, binding, flow, handle, "ACCOUNT"));
            assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider='github' AND provider_user_id=?",
                    Integer.class, providerId));
        }
    }

    @Test void accountMutationRejectsMissingServiceCredential() throws Exception {
        assertEquals(401, call("POST", "/api/account/reauth/password", "{\"password\":\"x\"}", null, null, null, null).statusCode());
        assertEquals(401, call("POST", "/api/account/social-links/github", "{}", null, null, null, null).statusCode());
        assertEquals(401, call("DELETE", "/api/account/social-links/github", "{}", null, null, null, null).statusCode());
    }

    @Test void logoutInvalidatesUnstartedAccountIntent() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        String proof = accountChanges.passwordProof(handle, "safe-test-password-123");
        String binding = Secrets.randomToken(), flow = Secrets.randomToken();
        String url = accountChanges.linkStart(handle, "github", proof, Secrets.sha256(binding), flow);
        String intent = url.substring(url.indexOf("intent=") + 7);
        assertTrue(oauthFlows.startAvailable(intent, "github"));
        assertEquals(204, bff("POST", "/api/auth/logout", null, handle).statusCode());
        assertFalse(oauthFlows.startAvailable(intent, "github"));
        assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.claimStart(intent, "github", Secrets.randomToken()));
    }

    @Test void accountMeReturnsOnlyVerifiedEmailAccountFields() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        JsonNode login = verifiedLogin(email);
        String handle = login.get("sessionHandle").asText();
        var response = bff("GET", "/api/account/me", null, handle);
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.headers().firstValue("cache-control").orElse("").contains("no-store"));
        JsonNode profile = json.readTree(response.body());
        assertEquals(java.util.Set.of("userId", "displayName", "email", "emailLoginEnabled", "socialProviders", "createdAt", "deletionStatus"),
                java.util.stream.StreamSupport.stream(
                        java.util.Spliterators.spliteratorUnknownSize(profile.fieldNames(), 0), false)
                        .collect(java.util.stream.Collectors.toSet()));
        UUID userId = UUID.fromString(login.get("userId").asText());
        assertEquals(userId.toString(), profile.get("userId").asText());
        assertEquals("Test User", profile.get("displayName").asText());
        assertEquals(email, profile.get("email").asText());
        assertTrue(profile.get("emailLoginEnabled").asBoolean());
        assertTrue(profile.get("socialProviders").isEmpty());
        assertEquals("NONE", profile.get("deletionStatus").asText());
        assertEquals(db.queryForObject("SELECT created_at FROM auth.devfield_user WHERE id=?", java.sql.Timestamp.class, userId).toInstant(),
                Instant.parse(profile.get("createdAt").asText()));
        assertFalse(response.body().contains(handle));
        assertFalse(response.body().contains("password_hash"));
        assertFalse(response.body().contains("sessionHandle"));
        assertEquals(400, bff("GET", "/api/account/me?userId=" + UUID.randomUUID(), null, handle).statusCode());
        assertEquals(400, bff("GET", "/api/account/me", "{\"userId\":\"" + UUID.randomUUID() + "\"}", handle).statusCode());
    }

    @Test void accountMeSocialMethodsDoNotInventProfileData() throws Exception {
        String providerEmail = "provider-" + UUID.randomUUID() + "@example.test";
        String providerId = "account-me-github-" + UUID.randomUUID();
        var login = socialLogin("github", providerId, providerEmail);
        db.update("INSERT INTO auth.social_identity(id,user_id,provider,provider_user_id) VALUES (?,?,?,?)",
                UUID.randomUUID(), login.userId(), "kakao", "account-me-kakao-" + UUID.randomUUID());
        var response = bff("GET", "/api/account/me", null, login.sessionHandle());
        assertEquals(200, response.statusCode(), response.body());
        JsonNode profile = json.readTree(response.body());
        assertEquals(login.userId().toString(), profile.get("userId").asText());
        assertTrue(profile.get("displayName").isNull());
        assertTrue(profile.get("email").isNull());
        assertFalse(profile.get("emailLoginEnabled").asBoolean());
        assertEquals(java.util.List.of("GITHUB", "KAKAO"),
                java.util.stream.StreamSupport.stream(profile.get("socialProviders").spliterator(), false).map(JsonNode::asText).toList());
        assertFalse(response.body().contains(providerEmail));
        assertFalse(response.body().contains(providerId));
        assertFalse(response.body().contains(login.sessionHandle()));
        assertFalse(response.body().contains("provider_user_id"));
    }

    @Test void accountMeRequiresBffAndValidOwnSession() throws Exception {
        JsonNode first = verifiedLogin(UUID.randomUUID() + "@example.test");
        JsonNode second = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = first.get("sessionHandle").asText();
        String path = "/api/account/me";
        assertEquals(401, bff("GET", path, null, null).statusCode());
        assertEquals(401, bff("GET", path, null, Secrets.randomToken()).statusCode());
        assertEquals(401, call("GET", path, null, null, null, handle, null).statusCode());
        assertEquals(401, call("GET", path, null, "bff", "wrong-bff-credential-with-sufficient-entropy", handle, null).statusCode());
        assertEquals(403, call("GET", path, null, "project", PROJECT, handle, null).statusCode());
        assertEquals(403, call("GET", path, null, "interview", INTERVIEW, handle, null).statusCode());
        var own = bff("GET", path, null, handle);
        assertEquals(first.get("userId").asText(), json.readTree(own.body()).get("userId").asText());
        assertNotEquals(second.get("userId").asText(), json.readTree(own.body()).get("userId").asText());

        db.update("UPDATE auth.auth_session SET revoked_at=now() WHERE session_handle_hash=?", Secrets.sha256(handle));
        var revoked = bff("GET", path, null, handle);
        assertEquals(401, revoked.statusCode());
        assertTrue(revoked.headers().firstValue("cache-control").orElse("").contains("no-store"));
        String secondHandle = second.get("sessionHandle").asText();
        db.update("UPDATE auth.auth_session SET created_at=now()-interval '2 days',expires_at=now()-interval '1 second' " +
                "WHERE session_handle_hash=?", Secrets.sha256(secondHandle));
        assertEquals(401, bff("GET", path, null, secondHandle).statusCode());
    }

    @Test void accountMeAllowsDeletingWithoutGrantingJwtAndBlocksDeleted() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        UUID userId = UUID.fromString(login.get("userId").asText());
        db.update("UPDATE auth.devfield_user SET state='DELETING' WHERE id=?", userId);
        var deleting = bff("GET", "/api/account/me", null, handle);
        assertEquals(200, deleting.statusCode(), deleting.body());
        assertEquals("DELETING", json.readTree(deleting.body()).get("deletionStatus").asText());
        assertEquals(403, bff("POST", "/internal/auth/session-token", null, handle).statusCode());
        db.update("UPDATE auth.devfield_user SET state='DELETED' WHERE id=?", userId);
        var deleted = bff("GET", "/api/account/me", null, handle);
        assertEquals(401, deleted.statusCode());
        assertTrue(deleted.headers().firstValue("cache-control").orElse("").contains("no-store"));
    }

    @Test void accountMeDatabaseFailureDoesNotExposeData() throws Exception {
        JsonNode login = verifiedLogin(UUID.randomUUID() + "@example.test");
        String handle = login.get("sessionHandle").asText();
        db.execute("ALTER TABLE auth.social_identity RENAME TO social_identity_temporarily_unavailable");
        try {
            var response = bff("GET", "/api/account/me", null, handle);
            assertEquals(503, response.statusCode());
            assertEquals("auth_unavailable", json.readTree(response.body()).get("code").asText());
            assertTrue(response.headers().firstValue("cache-control").orElse("").contains("no-store"));
            assertFalse(response.body().contains(handle));
        } finally {
            db.execute("ALTER TABLE auth.social_identity_temporarily_unavailable RENAME TO social_identity");
        }
    }

    @Test void migrationAndEmailLifecycle() throws Exception {
        assertEquals(6, db.queryForObject("SELECT count(*) FROM auth.flyway_schema_history WHERE success", Integer.class));
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

    @Test void v3UpgradesPopulatedV1V2WithoutLosingEmailOrSession() throws Exception {
        String upgradeUrl = PG.getJdbcUrl().replace("/auth_test", "/auth_upgrade");
        try (Connection connection = DriverManager.getConnection(PG.getJdbcUrl(), PG.getUsername(), PG.getPassword());
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE auth_upgrade OWNER " + PG.getUsername());
        }
        try (Connection connection = DriverManager.getConnection(upgradeUrl, PG.getUsername(), PG.getPassword());
             var statement = connection.createStatement()) { statement.execute("CREATE SCHEMA auth"); }
        var v2 = Flyway.configure().dataSource(upgradeUrl, PG.getUsername(), PG.getPassword())
                .schemas("auth").defaultSchema("auth").locations("classpath:db/migration")
                .target(org.flywaydb.core.api.MigrationVersion.fromVersion("2")).load();
        assertEquals(2, v2.migrate().migrationsExecuted);
        UUID user = UUID.randomUUID();
        UUID credential = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        try (Connection connection = DriverManager.getConnection(upgradeUrl, PG.getUsername(), PG.getPassword());
             var statement = connection.createStatement()) {
            statement.execute("INSERT INTO auth.devfield_user(id,display_name) VALUES ('" + user + "','Existing User')");
            statement.execute("INSERT INTO auth.email_credential(id,user_id,normalized_email,password_hash,verified_at) VALUES ('" +
                    credential + "','" + user + "','existing@example.test','" + "x".repeat(64) + "',now())");
            statement.execute("INSERT INTO auth.auth_session(id,user_id,session_handle_hash,expires_at) VALUES ('" +
                    session + "','" + user + "','" + "a".repeat(64) + "',now()+interval '1 day')");
        }
        var v3 = Flyway.configure().dataSource(upgradeUrl, PG.getUsername(), PG.getPassword())
                .schemas("auth").defaultSchema("auth").locations("classpath:db/migration").load();
        assertEquals(4, v3.migrate().migrationsExecuted);
        assertEquals(0, v3.migrate().migrationsExecuted);
        try (Connection connection = DriverManager.getConnection(upgradeUrl, PG.getUsername(), PG.getPassword());
             var statement = connection.createStatement()) {
            try (var rows = statement.executeQuery("SELECT count(*) FROM auth.email_credential c JOIN auth.devfield_user u ON c.user_id=u.id JOIN auth.auth_session s ON s.user_id=u.id WHERE c.normalized_email='existing@example.test' AND s.revoked_at IS NULL")) {
                assertTrue(rows.next());
                assertEquals(1, rows.getInt(1));
            }
        }
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

    @Test void oauthIntentHandoffAndSocialReloginAreAtomic() {
        String binding = Secrets.randomToken();
        String flow = Secrets.randomToken();
        String url = oauthFlows.createIntent("kakao", Secrets.sha256(binding), flow, "SIGNUP_COMPLETE");
        String intent = url.substring(url.indexOf("intent=") + 7);
        String state = Secrets.randomToken();
        oauthFlows.claimStart(intent, "kakao", state);
        assertThrows(dev.devfield.auth.api.ApiError.class, () -> oauthFlows.claimStart(intent, "kakao", Secrets.randomToken()));
        oauthFlows.saveRequest(state, new byte[]{1, 2, 3});
        assertArrayEquals(new byte[]{1, 2, 3}, oauthFlows.requestBytes(state, true));
        assertNull(oauthFlows.requestBytes(state, true));
        String handoff = oauthFlows.createHandoff(state, "kakao", "stable-kakao-test-id", null);
        var mismatch = assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, Secrets.randomToken(), flow));
        assertEquals(400, mismatch.status().value());
        var first = oauthFlows.exchange(handoff, binding, flow, null, "SIGNUP");
        assertNotNull(first.sessionHandle());
        assertThrows(dev.devfield.auth.api.ApiError.class, () -> oauthFlows.exchange(handoff, binding, flow));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider='kakao' AND provider_user_id='stable-kakao-test-id' AND provider_email IS NULL", Integer.class));

        String secondBinding = Secrets.randomToken();
        String secondFlow = Secrets.randomToken();
        String secondUrl = oauthFlows.createIntent("kakao", Secrets.sha256(secondBinding), secondFlow, "LOGIN_COMPLETE");
        String secondState = Secrets.randomToken();
        oauthFlows.claimStart(secondUrl.substring(secondUrl.indexOf("intent=") + 7), "kakao", secondState);
        String secondHandoff = oauthFlows.createHandoff(secondState, "kakao", "stable-kakao-test-id", null);
        var second = oauthFlows.exchange(secondHandoff, secondBinding, secondFlow);
        assertEquals(first.userId(), second.userId());
        assertNotEquals(first.sessionHandle(), second.sessionHandle());
    }

    @Test void matchingProviderEmailDoesNotMergeWithEmailCredential() throws Exception {
        String email = UUID.randomUUID() + "@example.test";
        UUID emailUser = UUID.fromString(verifiedLogin(email).get("userId").asText());
        String binding = Secrets.randomToken();
        String flow = Secrets.randomToken();
        String intentUrl = oauthFlows.createIntent("github", Secrets.sha256(binding), flow, "SIGNUP_COMPLETE");
        String state = Secrets.randomToken();
        oauthFlows.claimStart(intentUrl.substring(intentUrl.indexOf("intent=") + 7), "github", state);
        String handoff = oauthFlows.createHandoff(state, "github", "different-provider-id-" + UUID.randomUUID(), email);
        UUID socialUser = oauthFlows.exchange(handoff, binding, flow, null, "SIGNUP").userId();
        assertNotEquals(emailUser, socialUser);
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=?", Integer.class, emailUser));
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=?", Integer.class, socialUser));
    }

    @Test void oauthHttpIntentAndAuthorizationStartRequireBffAndSingleUse() throws Exception {
        String flow = Secrets.randomToken();
        String binding = Secrets.randomToken();
        String payload = json.writeValueAsString(java.util.Map.of("provider", "github", "browserBindingHash", Secrets.sha256(binding),
                "returnRoute", "LOGIN_COMPLETE", "flowId", flow));
        assertEquals(401, call("POST", "/internal/auth/oauth-intents", payload, null, null, null, null).statusCode());
        var created = bff("POST", "/internal/auth/oauth-intents", payload, null);
        assertEquals(201, created.statusCode());
        String url = json.readTree(created.body()).get("authorizationUrl").asText();
        String path = URI.create(url).getRawPath() + "?" + URI.create(url).getRawQuery();
        var started = call("GET", path, null, null, null, null, null);
        assertEquals(302, started.statusCode());
        assertTrue(started.headers().firstValue("location").orElse("").startsWith("http://127.0.0.1:" + MOCK_PROVIDER.getAddress().getPort() + "/authorize?"));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE flow_id=? AND started_at IS NOT NULL AND oauth_request IS NOT NULL", Integer.class, flow));
        assertEquals(410, call("GET", path, null, null, null, null, null).statusCode());
        assertEquals(404, call("GET", "/oauth2/authorization/unknown?intent=" + Secrets.randomToken(), null, null, null, null, null).statusCode());
        assertEquals(400, call("GET", "/oauth2/authorization/github?intent=bad", null, null, null, null, null).statusCode());
        assertEquals(410, call("GET", "/oauth2/authorization/github?intent=" + Secrets.randomToken(), null, null, null, null, null).statusCode());
        assertEquals(400, bff("POST", "/internal/auth/oauth-intents", payload.replace("github", "unknown"), null).statusCode());
    }

    @Test void disabledProviderStartReturns503() throws Exception {
        OAuthProviders disabled = new OAuthProviders("", "", "", "", "", "", "http://127.0.0.1:18080");
        var request = new MockHttpServletRequest("GET", "/oauth2/authorization/kakao");
        request.setServletPath("/oauth2/authorization/kakao");
        request.setParameter("intent", Secrets.randomToken());
        var response = new MockHttpServletResponse();
        new OAuthStartValidationFilter(oauthFlows, disabled).doFilter(request, response, new MockFilterChain());
        assertEquals(503, response.getStatus());
        assertTrue(response.getContentAsString().contains("provider_unavailable"));
    }

    @Test void oauthStartQuotaIsAtomicAndRecoversAfterWindow() throws Exception {
        int recent = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' AND created_at>now()-interval '2 seconds'", Integer.class);
        OAuthFlowStore limited = new OAuthFlowStore(db, "http://127.0.0.1:18080", Duration.ofMinutes(5),
                Duration.ofMinutes(2), Duration.ofDays(1), Duration.ofSeconds(2), recent + 2, 1000);
        String bindingHash = Secrets.sha256(Secrets.randomToken());
        startLimited(limited, "github", bindingHash);
        startLimited(limited, "google", bindingHash);
        var blocked = assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> startLimited(limited, "kakao", bindingHash));
        assertEquals(429, blocked.status().value());
        int afterBlock = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class);
        assertEquals(afterBlock, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class));
        Thread.sleep(2100);
        startLimited(limited, "github", bindingHash);

        int baseline = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' AND created_at>now()-interval '1 hour'", Integer.class);
        OAuthFlowStore oneMore = new OAuthFlowStore(db, "http://127.0.0.1:18080", Duration.ofMinutes(5),
                Duration.ofMinutes(2), Duration.ofDays(1), Duration.ofHours(1), baseline + 1, 1000);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            Future<Integer> a = workers.submit(() -> quotaAttempt(oneMore, bindingHash, ready, go));
            Future<Integer> b = workers.submit(() -> quotaAttempt(oneMore, bindingHash, ready, go));
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            assertEquals(java.util.Set.of(201, 429), java.util.Set.of(a.get(), b.get()));
        }
        assertEquals(baseline + 1, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' AND created_at>now()-interval '1 hour'", Integer.class));
    }

    private int quotaAttempt(OAuthFlowStore store, String bindingHash, CountDownLatch ready, CountDownLatch go) throws Exception {
        ready.countDown();
        go.await();
        try { startLimited(store, "github", bindingHash); return 201; }
        catch (dev.devfield.auth.api.ApiError error) { return error.status().value(); }
    }

    private void startLimited(OAuthFlowStore store, String provider, String bindingHash) {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                store.createIntent(provider, bindingHash, Secrets.randomToken(), "LOGIN_COMPLETE"));
    }

    @Test void oauthActiveIntentCapPreventsAdditionalRows() {
        int active = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' AND expires_at>now()", Integer.class);
        OAuthFlowStore capped = new OAuthFlowStore(db, "http://127.0.0.1:18080", Duration.ofMinutes(5),
                Duration.ofMinutes(2), Duration.ofDays(1), Duration.ofMinutes(1), 10000, active + 1);
        String bindingHash = Secrets.sha256(Secrets.randomToken());
        startLimited(capped, "github", bindingHash);
        int before = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class);
        assertEquals(429, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> startLimited(capped, "google", bindingHash)).status().value());
        assertEquals(before, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class));
    }

    @Test void oauthHttpQuotaReturns429WithoutAddingIntent() throws Exception {
        int recent = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' AND created_at>now()-interval '1 minute'", Integer.class);
        java.util.List<UUID> filler = new java.util.ArrayList<>();
        try {
            for (int i = recent; i < 120; i++) {
                UUID id = UUID.randomUUID();
                filler.add(id);
                db.update("INSERT INTO auth.action_token(id,purpose,token_hash,expires_at,provider,flow_id,browser_binding_hash,return_route) " +
                        "VALUES (?,'OAUTH_INTENT_LOGIN',?,now()+interval '5 minutes','github',?,?,'LOGIN_COMPLETE')",
                        id, Secrets.sha256(Secrets.randomToken()), Secrets.randomToken(), Secrets.sha256(Secrets.randomToken()));
            }
            String body = json.writeValueAsString(java.util.Map.of("provider", "github", "browserBindingHash", Secrets.sha256(Secrets.randomToken()),
                    "flowId", Secrets.randomToken(), "returnRoute", "LOGIN_COMPLETE"));
            int before = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class);
            var response = bff("POST", "/internal/auth/oauth-intents", body, null);
            assertEquals(429, response.statusCode(), response.body());
            assertEquals(before, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='OAUTH_INTENT_LOGIN'", Integer.class));
        } finally {
            for (UUID id : filler) db.update("DELETE FROM auth.action_token WHERE id=?", id);
        }
    }

    @Test void oauthCleanupIsBatchedFkSafeAndPreservesOtherData() {
        while (oauthFlows.cleanupOAuth(1000) > 0) { /* drain only already due OAuth rows */ }
        String binding = Secrets.randomToken();
        String flow = Secrets.randomToken();
        String url = oauthFlows.createIntent("github", Secrets.sha256(binding), flow, "SIGNUP_COMPLETE");
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
        String handoff = oauthFlows.createHandoff(state, "github", "cleanup-test-id", null);
        String otherFlow = Secrets.randomToken();
        String otherUrl = oauthFlows.createIntent("google", Secrets.sha256(binding), otherFlow, "LOGIN_COMPLETE");
        String otherState = Secrets.randomToken();
        oauthFlows.claimStart(otherUrl.substring(otherUrl.indexOf("intent=") + 7), "google", otherState);
        oauthFlows.createHandoff(otherState, "google", "cleanup-other-id", null);
        String liveFlow = Secrets.randomToken();
        oauthFlows.createIntent("kakao", Secrets.sha256(binding), liveFlow, "LOGIN_COMPLETE");
        int verifyBefore = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='VERIFY_SIGNUP'", Integer.class);
        db.update("UPDATE auth.action_token SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 second' WHERE flow_id IN (?,?)", flow, otherFlow);
        assertEquals(2, oauthFlows.cleanupOAuth(1));
        assertEquals(2, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE flow_id IN (?,?)", Integer.class, flow, otherFlow));
        assertEquals(2, oauthFlows.cleanupOAuth(1));
        assertEquals(0, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE flow_id IN (?,?)", Integer.class, flow, otherFlow));
        assertEquals(0, oauthFlows.cleanupOAuth(1));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE flow_id=?", Integer.class, liveFlow));
        assertEquals(verifyBefore, db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose='VERIFY_SIGNUP'", Integer.class));
        assertEquals(410, assertThrows(dev.devfield.auth.api.ApiError.class,
                () -> oauthFlows.exchange(handoff, binding, flow)).status().value());
    }

    @Test void oauthCleanupRacingExchangeDoesNotLoseSession() throws Exception {
        String binding = Secrets.randomToken();
        String flow = Secrets.randomToken();
        String url = oauthFlows.createIntent("github", Secrets.sha256(binding), flow, "SIGNUP_COMPLETE");
        String state = Secrets.randomToken();
        oauthFlows.claimStart(url.substring(url.indexOf("intent=") + 7), "github", state);
        String handoff = oauthFlows.createHandoff(state, "github", "cleanup-race-" + UUID.randomUUID(), null);
        CountDownLatch go = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            Future<OAuthFlowStore.HandoffResult> exchange = workers.submit(() -> {
                go.await();
                return oauthFlows.exchange(handoff, binding, flow, null, "SIGNUP");
            });
            Future<Integer> cleanup = workers.submit(() -> {
                go.await();
                return oauthFlows.cleanupOAuth(1);
            });
            go.countDown();
            var result = exchange.get();
            cleanup.get();
            assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.auth_session WHERE session_handle_hash=? AND user_id=?",
                    Integer.class, Secrets.sha256(result.sessionHandle()), result.userId()));
            assertEquals(410, assertThrows(dev.devfield.auth.api.ApiError.class,
                    () -> oauthFlows.exchange(handoff, binding, flow)).status().value());
        }
    }

    @Test void mockProviderCallbackHandoffAndRelogin() throws Exception {
        String googleUser = mockProviderLogin("google");
        assertEquals(googleUser, mockProviderLogin("google"));
        String firstUser = mockProviderLogin("github");
        assertEquals(firstUser, mockProviderLogin("github"));
        String kakaoUser = mockProviderLogin("kakao");
        assertEquals(kakaoUser, mockProviderLogin("kakao"));
        assertNotEquals(firstUser, kakaoUser);
        assertNotEquals(googleUser, firstUser);
        assertNotEquals(googleUser, kakaoUser);
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider='google' AND provider_user_id='google-sub-654321'", Integer.class));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider='github' AND provider_user_id='654321'", Integer.class));
        assertEquals(1, db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider='kakao' AND provider_user_id='654321' AND provider_email IS NULL", Integer.class));
    }

    @Test void productionRegistrationUsesStableIdsAndMinimumScopes() {
        var providers = new OAuthProviders("google-id", "google-secret", "github-id", "github-secret",
                "kakao-id", "kakao-secret", "http://127.0.0.1:18080");
        assertEquals("sub", providers.findByRegistrationId("google").getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
        assertEquals(java.util.Set.of("openid"), providers.findByRegistrationId("google").getScopes());
        assertEquals("id", providers.findByRegistrationId("github").getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
        assertTrue(providers.findByRegistrationId("github").getScopes() == null || providers.findByRegistrationId("github").getScopes().isEmpty());
        assertEquals("id", providers.findByRegistrationId("kakao").getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
        assertTrue(providers.findByRegistrationId("kakao").getScopes() == null || providers.findByRegistrationId("kakao").getScopes().isEmpty());
    }

    private String mockProviderLogin(String provider) throws Exception {
        String providerId = "google".equals(provider) ? "google-sub-654321" : "654321";
        boolean existing = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider=? AND provider_user_id=?", Integer.class, provider, providerId) > 0;
        String purpose = existing ? "LOGIN" : "SIGNUP";
        String flow = Secrets.randomToken();
        String binding = Secrets.randomToken();
        String payload = json.writeValueAsString(java.util.Map.of("provider", provider, "browserBindingHash", Secrets.sha256(binding),
                "returnRoute", purpose + "_COMPLETE", "flowId", flow));
        var created = bff("POST", "/internal/auth/oauth-intents", payload, null);
        assertEquals(201, created.statusCode(), created.body());
        URI startUri = URI.create(json.readTree(created.body()).get("authorizationUrl").asText());
        var started = call("GET", startUri.getRawPath() + "?" + startUri.getRawQuery(), null, null, null, null, null);
        assertEquals(302, started.statusCode(), started.body());
        String authorize = started.headers().firstValue("location").orElseThrow();
        String state = java.util.Arrays.stream(URI.create(authorize).getRawQuery().split("&"))
                .filter(item -> item.startsWith("state=")).map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
        GOOGLE_NONCE.set("google".equals(provider) ? java.util.Arrays.stream(URI.create(authorize).getRawQuery().split("&"))
                .filter(item -> item.startsWith("nonce=")).map(item -> URLDecoder.decode(item.substring(6), StandardCharsets.UTF_8))
                .findFirst().orElseThrow() : null);
        var callback = call("GET", "/login/oauth2/code/" + provider + "?code=mock-code&state=" + state, null, null, null, null, null);
        GOOGLE_NONCE.set(null);
        assertEquals(303, callback.statusCode(), callback.body());
        URI location = URI.create(callback.headers().firstValue("location").orElseThrow());
        assertEquals("http://localhost:13000/auth/oauth/callback", location.getScheme() + "://" + location.getAuthority() + location.getPath());
        String handoff = java.util.Arrays.stream(location.getRawFragment().split("&"))
                .filter(item -> item.startsWith("handoff=")).map(item -> item.substring(8)).findFirst().orElseThrow();
        var exchanged = bff("POST", "/internal/auth/oauth-handoffs/exchange",
                json.writeValueAsString(java.util.Map.of("handoff", handoff, "browserBinding", binding, "flowId", flow, "expectedPurpose", purpose)), null);
        assertEquals(200, exchanged.statusCode(), exchanged.body());
        assertEquals(410, bff("POST", "/internal/auth/oauth-handoffs/exchange",
                json.writeValueAsString(java.util.Map.of("handoff", handoff, "browserBinding", binding, "flowId", flow, "expectedPurpose", purpose)), null).statusCode());
        return json.readTree(exchanged.body()).get("userId").asText();
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
