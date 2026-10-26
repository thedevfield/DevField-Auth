package dev.devfield.auth.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.devfield.auth.api.ApiError;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtTokens {
    public record Issued(String accessToken, String tokenType, Instant expiresAt) {}
    public record Identity(UUID userId, UUID sessionId) {}
    private final JwtKeys keys;
    private final String issuer;
    private final String audience;
    private final Duration ttl;

    public JwtTokens(JwtKeys keys, @Value("${devfield.auth.issuer}") String issuer,
                     @Value("${devfield.auth.audience}") String audience,
                     @Value("${devfield.auth.jwt-ttl}") Duration ttl) {
        if (issuer.isBlank() || audience.isBlank() || ttl.isNegative() || ttl.isZero())
            throw new IllegalArgumentException("Invalid JWT configuration");
        this.keys = keys; this.issuer = issuer; this.audience = audience; this.ttl = ttl;
    }

    public Map<String, Object> jwks() { return Map.of("keys", List.of(keys.key().toPublicJWK().toJSONObject())); }

    public Issued issue(UUID userId, UUID sessionId) {
        try {
            Instant now = Instant.now();
            Instant expiry = now.plus(ttl);
            JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer).audience(audience)
                    .subject(userId.toString()).issueTime(Date.from(now)).notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(expiry)).jwtID(UUID.randomUUID().toString())
                    .claim("sid", sessionId.toString()).build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keys.key().getKeyID())
                    .type(com.nimbusds.jose.JOSEObjectType.JWT).build(), claims);
            jwt.sign(new RSASSASigner(keys.key().toRSAPrivateKey()));
            return new Issued(jwt.serialize(), "Bearer", expiry);
        } catch (Exception e) { throw new IllegalStateException("JWT signing failed", e); }
    }

    public Identity verify(String bearer) {
        if (bearer == null || !bearer.startsWith("Bearer ")) throw invalid();
        try {
            SignedJWT jwt = SignedJWT.parse(bearer.substring(7));
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm()) ||
                    !com.nimbusds.jose.JOSEObjectType.JWT.equals(jwt.getHeader().getType()) ||
                    !keys.key().getKeyID().equals(jwt.getHeader().getKeyID()) ||
                    !jwt.verify(new RSASSAVerifier(keys.key().toRSAPublicKey()))) throw invalid();
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant now = Instant.now();
            if (!issuer.equals(claims.getIssuer()) || claims.getAudience() == null || !claims.getAudience().contains(audience) ||
                    claims.getIssueTime() == null || claims.getNotBeforeTime() == null || claims.getExpirationTime() == null ||
                    claims.getJWTID() == null || claims.getJWTID().isBlank() ||
                    claims.getIssueTime().toInstant().isAfter(now) || claims.getNotBeforeTime().toInstant().isAfter(now) ||
                    !claims.getExpirationTime().toInstant().isAfter(now)) throw invalid();
            return new Identity(UUID.fromString(claims.getSubject()), UUID.fromString(claims.getStringClaim("sid")));
        } catch (ApiError e) { throw e; }
        catch (Exception e) { throw invalid(); }
    }

    private static ApiError invalid() { return new ApiError(HttpStatus.UNAUTHORIZED, "invalid_token"); }
}
