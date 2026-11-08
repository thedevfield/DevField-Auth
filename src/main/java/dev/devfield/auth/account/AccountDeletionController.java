package dev.devfield.auth.account;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountDeletionController {
    public record Request(String reauthProof) {}
    private final AccountDeletion deletion;

    AccountDeletionController(AccountDeletion deletion) { this.deletion = deletion; }

    @DeleteMapping("/api/account/me")
    public ResponseEntity<?> delete(@RequestHeader(value = "X-DevField-Session-Handle", required = false) String handle,
                                    @RequestBody(required = false) Request request) {
        return deletion.request(handle, request == null ? null : request.reauthProof())
                ? ResponseEntity.noContent().build()
                : ResponseEntity.accepted().body(Map.of("deletionStatus", "DELETING"));
    }
}
