package dev.devfield.auth.api;

import dev.devfield.auth.account.AuthAccounts;
import dev.devfield.auth.security.JwtTokens;
import dev.devfield.auth.session.AuthSessions;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    public record Signup(String email, String password, String displayName) {}
    public record Verify(String token) {}
    public record Login(String email, String password) {}
    private final AuthAccounts accounts;
    private final AuthSessions sessions;
    private final JwtTokens tokens;

    public AuthController(AuthAccounts accounts, AuthSessions sessions, JwtTokens tokens) {
        this.accounts = accounts; this.sessions = sessions; this.tokens = tokens;
    }

    @PostMapping("/api/auth/signup")
    ResponseEntity<?> signup(@RequestBody Signup body) {
        accounts.signup(body.email(), body.password(), body.displayName());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("status", "verification_required"));
    }

    @PostMapping("/api/auth/verify-email")
    ResponseEntity<Void> verify(@RequestBody Verify body) {
        accounts.verify(body.token());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/auth/login")
    ResponseEntity<AuthAccounts.LoginResult> login(@RequestBody Login body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(accounts.login(body.email(), body.password()));
    }

    @PostMapping("/api/auth/logout")
    ResponseEntity<Void> logout(@RequestHeader(value = "X-DevField-Session-Handle", required = false) String handle) {
        sessions.logout(handle);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/auth/jwks")
    Map<String, Object> jwks() { return tokens.jwks(); }

    @PostMapping("/internal/auth/session-token")
    ResponseEntity<JwtTokens.Issued> token(@RequestHeader(value = "X-DevField-Session-Handle", required = false) String handle) {
        var state = sessions.byHandle(handle);
        sessions.requireActive(state);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(tokens.issue(state.userId(), state.id()));
    }

    @PostMapping("/internal/auth/session-check")
    ResponseEntity<Void> check(@RequestHeader(value = "Authorization", required = false) String bearer) {
        var identity = tokens.verify(bearer);
        sessions.requireActive(sessions.byId(identity.sessionId(), identity.userId()));
        return ResponseEntity.noContent().build();
    }
}
