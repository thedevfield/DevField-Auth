package dev.devfield.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.stereotype.Component;

@Component
public class OAuthRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private final OAuthFlowStore store;
    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public OAuthRequestRepository(OAuthFlowStore store, OAuthProviders providers,
                                  @Value("${AUTH_OAUTH_CONTEXT_KEY:}") String encodedKey) {
        this.store = store;
        byte[] decoded;
        try { decoded = encodedKey.isBlank() ? new byte[0] : Base64.getDecoder().decode(encodedKey); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("Invalid OAuth context key", e); }
        if (providers.anyEnabled() && decoded.length != 32) throw new IllegalArgumentException("OAuth context key is required with enabled providers");
        this.key = decoded.length == 32 ? new SecretKeySpec(decoded, "AES") : null;
    }

    @Override public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return read(request, false);
    }

    @Override public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return read(request, true);
    }

    private OAuth2AuthorizationRequest read(HttpServletRequest request, boolean consume) {
        String state = request.getParameter("state");
        if (state == null || key == null) return null;
        byte[] encrypted = store.requestBytes(state, consume);
        if (encrypted == null) return null;
        try {
            byte[] iv = Arrays.copyOfRange(encrypted, 0, 12);
            byte[] payload = Arrays.copyOfRange(encrypted, 12, encrypted.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            try (var input = new ObjectInputStream(new ByteArrayInputStream(cipher.doFinal(payload)))) {
                OAuth2AuthorizationRequest saved = (OAuth2AuthorizationRequest) input.readObject();
                return OAuth2AuthorizationRequest.from(saved).state(state).build();
            }
        } catch (Exception e) { throw new IllegalStateException("OAuth request could not be restored", e); }
    }

    @Override public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                                    HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) return;
        if (key == null) throw new IllegalStateException("OAuth is not configured");
        try {
            OAuth2AuthorizationRequest withoutState = OAuth2AuthorizationRequest.from(authorizationRequest).state("stored-state").build();
            var bytes = new ByteArrayOutputStream();
            try (var output = new ObjectOutputStream(bytes)) { output.writeObject(withoutState); }
            byte[] iv = new byte[12]; random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] data = cipher.doFinal(bytes.toByteArray());
            byte[] encrypted = new byte[iv.length + data.length];
            System.arraycopy(iv, 0, encrypted, 0, iv.length);
            System.arraycopy(data, 0, encrypted, iv.length, data.length);
            store.saveRequest(authorizationRequest.getState(), encrypted);
        } catch (Exception e) { throw new IllegalStateException("OAuth request could not be saved", e); }
    }
}
