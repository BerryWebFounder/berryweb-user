package com.berryweb.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Async
    public void sendEmailVerification(String email, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Email Verification - BerryWeb");
            message.setText("Please click the following link to verify your email: " +
                    "http://localhost:8081/api/auth/email/verify?token=" + token);

            mailSender.send(message);
            log.info("Email verification sent to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send email verification to: {}", email, e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String email, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Password Reset - BerryWeb");
            message.setText("Please click the following link to reset your password: " +
                    "http://localhost:8081/api/auth/password-reset/confirm?token=" + token);

            mailSender.send(message);
            log.info("Password reset email sent to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", email, e);
        }
    }

    @Async
    public void sendAccountLockNotification(String email, String username) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Account Locked - BerryWeb");
            message.setText("Your account '" + username + "' has been locked due to multiple failed login attempts. " +
                    "Please contact support if you need assistance.");

            mailSender.send(message);
            log.info("Account lock notification sent to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send account lock notification to: {}", email, e);
        }
    }

}
