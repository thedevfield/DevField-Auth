package dev.devfield.auth.oauth;

import dev.devfield.auth.api.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class OAuthIntentResolver implements OAuth2AuthorizationRequestResolver {
    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final OAuthFlowStore store;

    public OAuthIntentResolver(OAuthProviders providers, OAuthFlowStore store) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(providers, "/oauth2/authorization");
        this.delegate.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        this.store = store;
    }

    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest result = delegate.resolve(request);
        return claim(request, result);
    }

    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest result = delegate.resolve(request, clientRegistrationId);
        return claim(request, result);
    }

    private OAuth2AuthorizationRequest claim(HttpServletRequest request, OAuth2AuthorizationRequest result) {
        if (result == null) return null;
        String path = request.getServletPath();
        String provider = path.substring(path.lastIndexOf('/') + 1);
        if (request.getParameter("intent") == null) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_intent");
        store.claimStart(request.getParameter("intent"), provider, result.getState());
        return result;
    }
}
