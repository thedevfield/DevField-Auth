package dev.devfield.auth.oauth;

import dev.devfield.auth.api.ApiError;
import java.net.URI;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthController {
    public record IntentRequest(String provider, String browserBindingHash, String returnRoute, String flowId) {}
    public record ExchangeRequest(String handoff, String browserBinding, String flowId) {}
    private final OAuthFlowStore store;
    private final OAuthProviders providers;
    public OAuthController(OAuthFlowStore store, OAuthProviders providers) { this.store = store; this.providers = providers; }

    @PostMapping("/internal/auth/oauth-intents")
    ResponseEntity<?> createIntent(@RequestBody IntentRequest input) {
        if (!providers.enabled(input.provider())) throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, "provider_unavailable");
        String url = store.createIntent(input.provider(), input.browserBindingHash(), input.flowId(), input.returnRoute());
        return ResponseEntity.created(URI.create(url)).body(Map.of("authorizationUrl", url));
    }

    @PostMapping("/internal/auth/oauth-handoffs/exchange")
    OAuthFlowStore.HandoffResult exchange(@RequestBody ExchangeRequest input) {
        return store.exchange(input.handoff(), input.browserBinding(), input.flowId());
    }
}
