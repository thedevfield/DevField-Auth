package dev.devfield.auth.mail;

public interface VerificationMailer {
    void send(String email, String token);
}
