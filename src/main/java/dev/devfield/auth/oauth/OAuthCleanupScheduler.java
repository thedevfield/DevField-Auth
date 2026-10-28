package dev.devfield.auth.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class OAuthCleanupScheduler {
    private final OAuthFlowStore store;
    private final int batchSize;

    public OAuthCleanupScheduler(OAuthFlowStore store,
                                 @Value("${devfield.auth.oauth.cleanup-batch-size:100}") int batchSize) {
        if (batchSize < 1 || batchSize > 1000) throw new IllegalArgumentException("Invalid OAuth cleanup batch size");
        this.store = store;
        this.batchSize = batchSize;
    }

    @Scheduled(fixedDelayString = "${devfield.auth.oauth.cleanup-interval-ms:30000}",
            initialDelayString = "${devfield.auth.oauth.cleanup-interval-ms:30000}")
    public void cleanup() {
        store.cleanupOAuth(batchSize);
    }
}
