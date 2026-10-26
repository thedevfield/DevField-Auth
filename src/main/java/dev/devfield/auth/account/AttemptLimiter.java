package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class AttemptLimiter {
    private record Counter(int count, Instant since) {}
    private final ConcurrentHashMap<String, Counter> attempts = new ConcurrentHashMap<>();
    private final int max;
    private final Duration window;

    public AttemptLimiter(@Value("${devfield.auth.max-attempts}") int max,
                          @Value("${devfield.auth.attempt-window}") Duration window) {
        if (max < 1 || window.isNegative() || window.isZero()) throw new IllegalArgumentException("Invalid attempt policy");
        this.max = max;
        this.window = window;
    }

    public void check(String key) {
        Counter counter = attempts.get(key);
        if (counter != null && counter.since.plus(window).isAfter(Instant.now()) && counter.count >= max)
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
    }

    public void fail(String key) {
        Instant now = Instant.now();
        attempts.compute(key, (ignored, old) -> old == null || !old.since.plus(window).isAfter(now)
                ? new Counter(1, now) : new Counter(old.count + 1, old.since));
    }

    public void clear(String key) { attempts.remove(key); }
}
