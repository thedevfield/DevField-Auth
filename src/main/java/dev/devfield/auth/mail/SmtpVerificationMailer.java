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
    private final String linkUrl;
    private final String resetUrl;

    public SmtpVerificationMailer(JavaMailSender sender,
                                  @Value("${devfield.auth.mail-from}") String from,
                                  @Value("${devfield.auth.web-verify-url}") String verifyUrl,
                                  @Value("${devfield.auth.web-link-url}") String linkUrl,
                                  @Value("${devfield.auth.web-reset-url}") String resetUrl) {
        this.sender = sender;
        this.from = from;
        this.verifyUrl = verifyUrl;
        this.linkUrl = linkUrl;
        this.resetUrl = resetUrl;
        if (!verifyUrl.startsWith("https://") && !verifyUrl.startsWith("http://127.0.0.1:") &&
                !verifyUrl.startsWith("http://localhost:")) throw new IllegalArgumentException("Unsafe verification URL");
        for (String url : new String[]{linkUrl, resetUrl})
            if (!url.startsWith("https://") && !url.startsWith("http://127.0.0.1:") && !url.startsWith("http://localhost:"))
                throw new IllegalArgumentException("Unsafe mail URL");
    }

    @Override public void send(String email, String token) {
        send(email, token, verifyUrl, "Verify your DevField email");
    }
    @Override public void sendLink(String email, String token) {
        send(email, token, linkUrl, "Add your DevField email login");
    }
    @Override public void sendReset(String email, String token) {
        send(email, token, resetUrl, "Reset your DevField password");
    }
    private void send(String email, String token, String url, String subject) {
        var message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject(subject);
        message.setText("Open this link: " + url + "#token=" + token);
        sender.send(message);
    }
}
