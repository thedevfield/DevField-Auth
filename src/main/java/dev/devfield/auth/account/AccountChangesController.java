package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.oauth.OAuthFlowStore;
import java.net.URI;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AccountChangesController {
    public record PasswordRequest(String password) {}
    public record StartRequest(String browserBindingHash, String flowId, String reauthProof) {}
    public record UnlinkRequest(String reauthProof) {}
    private final AccountChanges changes;
    private final OAuthFlowStore flows;
    public AccountChangesController(AccountChanges changes, OAuthFlowStore flows) { this.changes = changes; this.flows = flows; }
    @PostMapping("/api/account/reauth/password")
    Map<String, String> password(@RequestHeader(value="X-DevField-Session-Handle", required=false) String handle,
                                 @RequestBody PasswordRequest request) {
        return Map.of("reauthProof", changes.passwordProof(handle, request.password()));
    }
    @PostMapping("/api/account/reauth/social/{provider}")
    ResponseEntity<?> social(@PathVariable String provider,
                             @RequestHeader(value="X-DevField-Session-Handle", required=false) String handle,
                             @RequestBody StartRequest request) {
        String url = changes.socialProofStart(handle, provider, request.browserBindingHash(), request.flowId());
        return ResponseEntity.created(URI.create(url)).body(Map.of("authorizationUrl", url));
    }
    @PostMapping("/api/account/social-links/{provider}")
    ResponseEntity<?> link(@PathVariable String provider,
                           @RequestHeader(value="X-DevField-Session-Handle", required=false) String handle,
                           @RequestBody StartRequest request) {
        String url = changes.linkStart(handle, provider, request.reauthProof(), request.browserBindingHash(), request.flowId());
        return ResponseEntity.created(URI.create(url)).body(Map.of("authorizationUrl", url));
    }
    @DeleteMapping("/api/account/social-links/{provider}")
    ResponseEntity<?> unlink(@PathVariable String provider,
                             @RequestHeader(value="X-DevField-Session-Handle", required=false) String handle,
                             @RequestBody UnlinkRequest request) {
        changes.unlink(handle, provider, request.reauthProof());
        return ResponseEntity.noContent().build();
    }
}
