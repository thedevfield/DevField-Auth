package dev.devfield.auth;

import static org.junit.jupiter.api.Assertions.*;

import dev.devfield.auth.mail.SmtpVerificationMailer;
import dev.devfield.auth.util.Secrets;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.testcontainers.containers.GenericContainer;

class SmtpVerificationMailerTest {
    @Test void sendsVerificationLinkAndResetThroughRealLocalSmtp() throws Exception {
        try (var mailpit = new GenericContainer<>("axllent/mailpit:v1.32.0").withExposedPorts(1025, 8025)) {
            mailpit.start();
            var sender = new JavaMailSenderImpl();
            sender.setHost(mailpit.getHost());
            sender.setPort(mailpit.getMappedPort(1025));
            sender.getJavaMailProperties().put("mail.smtp.connectiontimeout", "5000");
            sender.getJavaMailProperties().put("mail.smtp.timeout", "5000");
            var mailer = new SmtpVerificationMailer(sender, "devfield-test@example.test",
                    "http://localhost:13000/verify-email", "http://localhost:13000/account/email/verify",
                    "http://localhost:13000/reset-password/complete");
            String destination = "recipient@example.test";
            mailer.send(destination, Secrets.randomToken());
            mailer.sendLink(destination, Secrets.randomToken());
            mailer.sendReset(destination, Secrets.randomToken());
            var result = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://" + mailpit.getHost() + ":" +
                    mailpit.getMappedPort(8025) + "/api/v1/messages")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, result.statusCode());
            assertTrue(result.body().contains("Verify your DevField email"));
            assertTrue(result.body().contains("Add your DevField email login"));
            assertTrue(result.body().contains("Reset your DevField password"));
        }
    }
}
