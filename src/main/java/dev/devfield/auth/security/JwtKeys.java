package dev.devfield.auth.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtKeys {
    private final RSAKey key;

    public JwtKeys(@Value("${devfield.auth.private-key-path}") String privatePath,
                   @Value("${devfield.auth.public-key-path}") String publicPath) throws Exception {
        byte[] privateDer = pem(privatePath);
        byte[] publicDer = pem(publicPath);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(privateDer));
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(publicDer));
        if (publicKey.getModulus().bitLength() < 2048 || !privateKey.getModulus().equals(publicKey.getModulus()))
            throw new IllegalArgumentException("Invalid RSA signing key pair");
        String kid = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(publicDer));
        key = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).algorithm(JWSAlgorithm.RS256)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).build();
    }

    private static byte[] pem(String path) throws Exception {
        String value = Files.readString(Path.of(path));
        return Base64.getMimeDecoder().decode(value.replaceAll("-----[^-]+-----", ""));
    }

    public RSAKey key() { return key; }
}
