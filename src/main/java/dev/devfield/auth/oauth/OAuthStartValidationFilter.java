package dev.devfield.auth.oauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/** Gives invalid, expired, and reused starts the contracted response before Spring's redirect filter. */
public class OAuthStartValidationFilter extends OncePerRequestFilter {
    private final OAuthFlowStore store;
    private final OAuthProviders providers;
    public OAuthStartValidationFilter(OAuthFlowStore store, OAuthProviders providers) {
        this.store = store;
        this.providers = providers;
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                              FilterChain chain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (!"GET".equals(request.getMethod()) || !path.startsWith("/oauth2/authorization/")) {
            chain.doFilter(request, response);
            return;
        }
        String proof = request.getParameter("intent");
        String provider = path.substring("/oauth2/authorization/".length());
        if (!OAuthFlowStore.providerAllowed(provider)) { reject(response, 404, "unsupported_provider"); return; }
        if (!providers.enabled(provider)) { reject(response, 503, "provider_unavailable"); return; }
        if (proof == null || !OAuthFlowStore.flowAllowed(proof)) { reject(response, 400, "invalid_oauth_intent"); return; }
        if (!store.startAvailable(proof, provider)) { reject(response, 410, "oauth_intent_expired_or_used"); return; }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"code\":\"" + code + "\"}");
    }
}
