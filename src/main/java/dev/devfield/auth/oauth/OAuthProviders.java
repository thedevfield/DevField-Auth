package dev.devfield.auth.oauth;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

@Component
public class OAuthProviders implements ClientRegistrationRepository, Iterable<ClientRegistration> {
    private final List<ClientRegistration> registrations = new ArrayList<>();

    public OAuthProviders(@Value("${AUTH_GOOGLE_CLIENT_ID:}") String googleId,
                          @Value("${AUTH_GOOGLE_CLIENT_SECRET:}") String googleSecret,
                          @Value("${AUTH_GITHUB_CLIENT_ID:}") String githubId,
                          @Value("${AUTH_GITHUB_CLIENT_SECRET:}") String githubSecret,
                          @Value("${AUTH_KAKAO_CLIENT_ID:}") String kakaoId,
                          @Value("${AUTH_KAKAO_CLIENT_SECRET:}") String kakaoSecret,
                          @Value("${devfield.auth.oauth.browser-origin:http://127.0.0.1:18080}") String browserOrigin) {
        String redirect = browserOrigin + "/login/oauth2/code/{registrationId}";
        if (!googleId.isBlank() && !googleSecret.isBlank()) registrations.add(ClientRegistration.withRegistrationId("google")
                .clientId(googleId).clientSecret(googleSecret).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(redirect).scope("openid")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth").tokenUri("https://oauth2.googleapis.com/token")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs").issuerUri("https://accounts.google.com")
                .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo").userNameAttributeName("sub").clientName("Google").build());
        if (!githubId.isBlank() && !githubSecret.isBlank()) registrations.add(ClientRegistration.withRegistrationId("github")
                .clientId(githubId).clientSecret(githubSecret).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(redirect)
                .authorizationUri("https://github.com/login/oauth/authorize").tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user").userNameAttributeName("id").clientName("GitHub").build());
        if (!kakaoId.isBlank() && !kakaoSecret.isBlank()) registrations.add(ClientRegistration.withRegistrationId("kakao")
                .clientId(kakaoId).clientSecret(kakaoSecret).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(redirect)
                .authorizationUri("https://kauth.kakao.com/oauth/authorize").tokenUri("https://kauth.kakao.com/oauth/token")
                .userInfoUri("https://kapi.kakao.com/v2/user/me").userNameAttributeName("id").clientName("Kakao").build());
    }

    public boolean enabled(String provider) { return findByRegistrationId(provider) != null; }
    public boolean anyEnabled() { return !registrations.isEmpty(); }
    @Override public ClientRegistration findByRegistrationId(String id) {
        return registrations.stream().filter(x -> x.getRegistrationId().equals(id)).findFirst().orElse(null);
    }
    @Override public Iterator<ClientRegistration> iterator() { return List.copyOf(registrations).iterator(); }
}
