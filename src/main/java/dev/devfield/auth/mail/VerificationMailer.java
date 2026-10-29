package dev.devfield.auth.mail;

public interface VerificationMailer {
    void send(String email, String token);
    void sendLink(String email, String token);
    void sendReset(String email, String token);
}
