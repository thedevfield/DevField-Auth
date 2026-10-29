package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EmailAccountController {
    public record Email(String email) {}
    public record LinkRequest(String email, String reauthProof) {}
    public record Token(String token) {}
    public record Password(String password) {}
    public record ChangePassword(String currentPassword, String newPassword) {}
    public record Reset(String token, String password) {}
    private final EmailAccountManagement management;
    public EmailAccountController(EmailAccountManagement management) { this.management = management; }

    @PostMapping("/api/account/email-login/requests")
    ResponseEntity<?> requestLink(@RequestHeader(value="X-DevField-Session-Handle", required=false) String handle, @RequestBody LinkRequest body) {
        management.requestLink(handle, body.email(), body.reauthProof());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("status", "verification_required"));
    }
    @PostMapping("/api/account/email-login/verify")
    ResponseEntity<Void> verifyLink(@RequestHeader(value="X-DevField-Session-Handle", required=false) String handle, @RequestBody Token body) {
        management.verifyLink(handle, body.token());
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/api/account/email-login/password")
    ResponseEntity<Void> setPassword(@RequestHeader(value="X-DevField-Session-Handle", required=false) String handle, @RequestBody Password body) {
        management.setPassword(handle, body.password());
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/api/account/password/change")
    ResponseEntity<Void> changePassword(@RequestHeader(value="X-DevField-Session-Handle", required=false) String handle, @RequestBody ChangePassword body) {
        management.changePassword(handle, body.currentPassword(), body.newPassword());
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/api/auth/password-reset-requests")
    ResponseEntity<?> requestReset(@RequestBody Email body) {
        try { management.requestReset(body.email()); }
        catch (ApiError error) {
            if (!"mail_unavailable".equals(error.code())) throw error;
            // The transaction rolls back the token; the response still does not reveal account existence.
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("status", "accepted"));
    }
    @PostMapping("/api/auth/password-reset")
    ResponseEntity<Void> reset(@RequestBody Reset body) {
        management.resetPassword(body.token(), body.password());
        return ResponseEntity.noContent().build();
    }
}
