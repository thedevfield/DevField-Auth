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
    public OAuthStartValidationFilter(OAuthFlowStore store) { this.store = store; }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                              FilterChain chain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (!"GET".equals(request.getMethod()) || !path.startsWith("/oauth2/authorization/")) {
            chain.doFilter(request, response);
            return;
        }
        String proof = request.getParameter("intent");
        if (proof == null) { reject(response, 400, "invalid_oauth_intent"); return; }
        String provider = path.substring("/oauth2/authorization/".length());
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
