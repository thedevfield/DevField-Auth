package dev.devfield.auth.security;

import dev.devfield.auth.util.Secrets;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ServiceCredentialFilter extends OncePerRequestFilter {
    private final Map<String, String> hashes;

    public ServiceCredentialFilter(@Value("${devfield.auth.service-keys.bff}") String bff,
                                   @Value("${devfield.auth.service-keys.project}") String project,
                                   @Value("${devfield.auth.service-keys.interview}") String interview) {
        hashes = Map.of("bff", bff, "project", project, "interview", interview);
        for (String hash : hashes.values()) {
            if (!hash.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("Service key hash must be SHA-256 hex");
        }
        if (hashes.values().stream().distinct().count() != 3) throw new IllegalArgumentException("Service credentials must differ");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String caller = request.getHeader("X-DevField-Service");
        String key = request.getHeader("X-DevField-Service-Key");
        if (caller != null || key != null) {
            String expected = hashes.get(caller);
            if (expected == null || key == null || key.length() < 32 || key.length() > 512 ||
                    !Secrets.equalHex(expected, Secrets.sha256(key))) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            String path = request.getServletPath();
            boolean bffOnly = path.equals("/api/auth/signup") || path.equals("/api/auth/verify-email") ||
                    path.equals("/api/auth/login") || path.equals("/api/auth/logout") ||
                    path.equals("/internal/auth/session-token");
            boolean consumerOnly = path.equals("/internal/auth/session-check");
            if ((bffOnly && !caller.equals("bff")) || (consumerOnly && caller.equals("bff"))) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            var authentication = new UsernamePasswordAuthenticationToken(caller, null,
                    java.util.List.of(new SimpleGrantedAuthority("SERVICE_" + caller.toUpperCase(java.util.Locale.ROOT))));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        try { chain.doFilter(request, response); }
        finally { SecurityContextHolder.clearContext(); }
    }
}
