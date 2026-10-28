package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountMeController {
    private final AccountMe account;

    public AccountMeController(AccountMe account) { this.account = account; }

    @GetMapping("/api/account/me")
    ResponseEntity<AccountMe.Profile> me(
            @RequestHeader(value = "X-DevField-Session-Handle", required = false) String handle,
            HttpServletRequest request) {
        if (request.getQueryString() != null || request.getContentLengthLong() > 0 ||
                request.getHeader("Transfer-Encoding") != null)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(account.get(handle));
    }
}
