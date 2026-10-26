package dev.devfield.auth.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
public class SmtpVerificationMailer implements VerificationMailer {
    private final JavaMailSender sender;
    private final String from;
    private final String verifyUrl;

    public SmtpVerificationMailer(JavaMailSender sender,
                                  @Value("${devfield.auth.mail-from}") String from,
                                  @Value("${devfield.auth.web-verify-url}") String verifyUrl) {
        this.sender = sender;
        this.from = from;
        this.verifyUrl = verifyUrl;
        if (!verifyUrl.startsWith("https://") && !verifyUrl.startsWith("http://127.0.0.1:") &&
                !verifyUrl.startsWith("http://localhost:")) throw new IllegalArgumentException("Unsafe verification URL");
    }

    @Override public void send(String email, String token) {
        var message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("Verify your DevField email");
        message.setText("Open this link to verify your email: " + verifyUrl + "#token=" + token);
        sender.send(message);
    }
}
