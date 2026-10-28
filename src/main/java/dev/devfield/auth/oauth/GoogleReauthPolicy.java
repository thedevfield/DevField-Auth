package dev.devfield.auth.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class GoogleReauthPolicy {
    private final boolean identityOnlyEnabled;

    public GoogleReauthPolicy(@Value("${AUTH_GOOGLE_REAUTH_IDENTITY_ONLY_ENABLED:false}") boolean identityOnlyEnabled) {
        this.identityOnlyEnabled = identityOnlyEnabled;
    }

    public boolean identityOnlyEnabled() { return identityOnlyEnabled; }
}
