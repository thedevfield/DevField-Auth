package dev.devfield.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuthResultHandlers implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OAuthResultHandlers.class);
    private final OAuthFlowStore store;
    private final String callback;
    private final GoogleReauthPolicy googleReauthPolicy;
    public OAuthResultHandlers(OAuthFlowStore store,
                               @Value("${devfield.auth.oauth.web-callback:http://localhost:13000/auth/oauth/callback}") String callback,
                               GoogleReauthPolicy googleReauthPolicy) {
        this.store = store; this.callback = callback; this.googleReauthPolicy = googleReauthPolicy;
        if (!callback.matches("https?://[^#?]+/auth/oauth/callback")) throw new IllegalArgumentException("Invalid Web callback");
    }

    @Override public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                   Authentication authentication) throws IOException {
        OAuthFlowStore.Intent intent = null;
        try {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
            String provider = token.getAuthorizedClientRegistrationId();
            intent = store.byState(request.getParameter("state"));
            Object rawId = token.getPrincipal().getAttribute("google".equals(provider) ? "sub" : "id");
            if ("OAUTH_INTENT_REAUTH".equals(intent.purpose()) && "google".equals(provider)) {
                if (!(token.getPrincipal() instanceof org.springframework.security.oauth2.core.oidc.user.OidcUser user)) {
                    failure(response, "google_reauth_unavailable", intent); return;
                }
                rawId = user.getIdToken().getSubject();
                // Spring Security has validated the OIDC ID token before invoking this handler.
                if (!googleReauthPolicy.identityOnlyEnabled()) {
                    java.time.Instant authTime = user.getIdToken().getAuthenticatedAt();
                    java.time.Instant now = java.time.Instant.now();
                    if (authTime == null) { failure(response, "google_reauth_unavailable", intent); return; }
                    if (authTime.isAfter(now) || authTime.isBefore(now.minusSeconds(300))) {
                        failure(response, "google_reauth_stale", intent); return;
                    }
                }
            }
            if (rawId == null || rawId.toString().isBlank()) { failure(response, "oauth_identity_failed", intent); return; }
            String handoff = store.createHandoff(request.getParameter("state"), provider, rawId.toString(), null);
            redirect(response, "#flowId=" + intent.flowId() + "&handoff=" + handoff + "&purpose=" + intent.purpose().substring("OAUTH_INTENT_".length()));
        } catch (RuntimeException error) {
            String code = "oauth_callback_failed";
            if (error instanceof dev.devfield.auth.api.ApiError api) {
                if ("invalid_oauth_state".equals(api.code()) || "oauth_intent_expired_or_used".equals(api.code()))
                    code = "oauth_state_invalid";
                else if ("invalid_oauth_callback".equals(api.code())) code = "oauth_identity_failed";
            }
            failure(response, code, intent, error.getClass().getSimpleName());
        }
    }

    @Override public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                   org.springframework.security.core.AuthenticationException exception) throws IOException {
        OAuthFlowStore.Intent intent = null;
        try { intent = store.byState(request.getParameter("state")); }
        catch (RuntimeException ignored) { /* Missing or expired state has no safe flow context. */ }
        String providerError = request.getParameter("error");
        String springCode = exception instanceof org.springframework.security.oauth2.core.OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode() : "";
        String code = intent == null ? "oauth_state_invalid"
                : "access_denied".equals(providerError) ? "oauth_cancelled"
                : providerError != null ? "oauth_provider_rejected"
                : "authorization_request_not_found".equals(springCode) || "invalid_state_parameter".equals(springCode)
                    ? "oauth_state_invalid" : "oauth_callback_failed";
        failure(response, code, intent, exception.getClass().getSimpleName());
    }

    private void failure(HttpServletResponse response, String code, OAuthFlowStore.Intent intent) {
        failure(response, code, intent, "validation");
    }

    private void failure(HttpServletResponse response, String code, OAuthFlowStore.Intent intent, String causeType) {
        String ref = UUID.randomUUID().toString();
        LOG.warn("oauth_result_failure ref={} code={} causeType={}", ref, code, causeType);
        redirect(response, "#error=" + code + (intent == null ? "" : "&flowId=" + intent.flowId() +
                "&purpose=" + intent.purpose().substring("OAUTH_INTENT_".length())) + "&ref=" + ref);
    }
    private void redirect(HttpServletResponse response, String fragment) {
        response.setStatus(303);
        response.setHeader("Location", callback + fragment);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
    }
}
