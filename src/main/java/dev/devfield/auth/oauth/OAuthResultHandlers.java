package dev.devfield.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuthResultHandlers implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    private final OAuthFlowStore store;
    private final String callback;
    public OAuthResultHandlers(OAuthFlowStore store,
                               @Value("${devfield.auth.oauth.web-callback:http://localhost:13000/auth/oauth/callback}") String callback) {
        this.store = store; this.callback = callback;
        if (!callback.matches("https?://[^#?]+/auth/oauth/callback")) throw new IllegalArgumentException("Invalid Web callback");
    }

    @Override public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                   Authentication authentication) throws IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String state = request.getParameter("state");
        String provider = token.getAuthorizedClientRegistrationId();
        Object rawId = token.getPrincipal().getAttribute("google".equals(provider) ? "sub" : "id");
        if (rawId == null) { failure(response); return; }
        try {
            OAuthFlowStore.Intent intent = store.byState(state);
            String handoff = store.createHandoff(state, provider, rawId.toString(), null);
            redirect(response, "#flowId=" + intent.flowId() + "&handoff=" + handoff);
        } catch (RuntimeException error) {
            failure(response);
        }
    }

    @Override public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                   org.springframework.security.core.AuthenticationException exception) throws IOException {
        String flow = "";
        try { flow = store.byState(request.getParameter("state")).flowId(); }
        catch (Exception ignored) { }
        redirect(response, "#error=oauth_cancelled" + (flow.isEmpty() ? "" : "&flowId=" + flow));
    }

    private void failure(HttpServletResponse response) throws IOException { redirect(response, "#error=oauth_failed"); }
    private void redirect(HttpServletResponse response, String fragment) {
        response.setStatus(303);
        response.setHeader("Location", callback + fragment);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
    }
}
