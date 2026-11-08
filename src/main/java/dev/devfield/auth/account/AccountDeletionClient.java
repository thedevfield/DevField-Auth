package dev.devfield.auth.account;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
class AccountDeletionClient {
    private record Target(URI origin, String key) {
        static Target of(String url, String key) {
            if (url.isBlank() && key.isBlank()) return null;
            URI origin = URI.create(url);
            String host = origin.getHost();
            boolean loopback = "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
            if (host == null || !("https".equals(origin.getScheme()) || loopback && "http".equals(origin.getScheme()))
                    || origin.getRawUserInfo() != null || origin.getRawQuery() != null || origin.getRawFragment() != null
                    || !(origin.getPath().isEmpty() || "/".equals(origin.getPath())) || !key.matches("[!-~]{32,512}"))
                throw new IllegalArgumentException("Invalid account deletion service configuration");
            return new Target(origin, key);
        }
    }

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final Target project;
    private final Target interview;
    private final Duration timeout;

    AccountDeletionClient(@Value("${devfield.auth.deletion.project-url:}") String projectUrl,
                          @Value("${devfield.auth.deletion.project-key:}") String projectKey,
                          @Value("${devfield.auth.deletion.interview-url:}") String interviewUrl,
                          @Value("${devfield.auth.deletion.interview-key:}") String interviewKey,
                          @Value("${devfield.auth.deletion.timeout:PT3S}") Duration timeout) {
        project = Target.of(projectUrl, projectKey);
        interview = Target.of(interviewUrl, interviewKey);
        if (project != null && interview != null && projectKey.equals(interviewKey))
            throw new IllegalArgumentException("Account deletion requires independent service keys");
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(10)) > 0)
            throw new IllegalArgumentException("Invalid account deletion timeout");
        this.timeout = timeout;
    }

    boolean configured() { return project != null && interview != null; }

    int delete(boolean projectService, UUID user, UUID job) throws InterruptedException {
        Target target = projectService ? project : interview;
        String body = "{\"userId\":\"" + user + "\",\"deletionJobId\":\"" + job + "\",\"state\":\"DELETING\"}";
        var request = HttpRequest.newBuilder(target.origin().resolve("/internal/users/" + user + "/data"))
                .timeout(timeout).header("Content-Type", "application/json")
                .header("X-DevField-Service", "auth").header("X-DevField-Service-Key", target.key())
                .method("DELETE", HttpRequest.BodyPublishers.ofString(body)).build();
        try {
            return http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException e) {
            return 503;
        }
    }
}
