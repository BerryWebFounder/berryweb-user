package com.berryweb.user.service;

import com.berryweb.user.dto.*;
import com.berryweb.user.entity.User;
import com.berryweb.user.entity.UserSession;
import com.berryweb.user.exception.ResourceNotFoundException;
import com.berryweb.user.repository.UserRepository;
import com.berryweb.user.repository.UserRoleHistoryRepository;
import com.berryweb.user.repository.UserSessionRepository;
import com.berryweb.user.security.CustomUserPrincipal;
import com.berryweb.user.security.JwtTokenProvider;
import jakarta.ws.rs.BadRequestException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final UserRoleHistoryRepository roleHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final EmailService emailService;

    @Value("${app.security.max-login-attempts}")
    private int maxLoginAttempts;

    @Value("${app.security.account-lock-time}")
    private int accountLockTimeSeconds;

    @Value("${app.security.session-timeout}")
    private int sessionTimeoutHours;

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByUsernameOrEmail(request.getUsernameOrEmail(), request.getUsernameOrEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        // Check if account is locked
        if (user.getIsLocked()) {
            if (user.getLockedAt().plusSeconds(accountLockTimeSeconds).isAfter(LocalDateTime.now())) {
                throw new BadCredentialsException("Account is locked due to too many failed attempts");
            } else {
                // Auto-unlock if lock period has passed
                user.unlockAccount();
                userRepository.save(user);
            }
        }

        // Check if account is active
        if (!user.getIsActive()) {
            throw new BadCredentialsException("Account is deactivated");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword())
            );

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            String jwt = tokenProvider.generateToken(userPrincipal);

            // Create session
            UserSession session = UserSession.createSession(
                    user, jwt, request.getIpAddress(), request.getUserAgent(), sessionTimeoutHours
            );
            sessionRepository.save(session);

            // Update user login info
            user.updateLastLogin(request.getIpAddress());
            userRepository.save(user);

            // Convert to DTO
            UserDto userDto = convertToUserDto(user);

            return LoginResponse.builder()
                    .token(jwt)
                    .user(userDto)
                    .loginTime(LocalDateTime.now())
                    .build();

        } catch (BadCredentialsException ex) {
            // Handle failed login attempt
            user.incrementFailedLoginAttempts();

            if (user.getFailedLoginAttempts() >= maxLoginAttempts) {
                user.lockAccount();
                log.warn("Account locked for user: {} due to {} failed attempts", user.getUsername(), user.getFailedLoginAttempts());
            }

            userRepository.save(user);
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    public UserDto register(RegisterRequest request) {
        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username is already taken");
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email is already registered");
        }

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .phone(request.getPhone())
                .role(User.Role.USER)
                .emailVerificationToken(UUID.randomUUID().toString())
                .emailVerificationSentAt(LocalDateTime.now())
                .build();

        user = userRepository.save(user);

        // Send verification email
        emailService.sendEmailVerification(user.getEmail(), user.getEmailVerificationToken());

        return convertToUserDto(user);
    }

    public void logout(String token) {
        sessionRepository.findBySessionToken(token)
                .ifPresent(sessionRepository::delete);
    }

    public void logoutAllDevices(Long userId) {
        sessionRepository.deleteAllUserSessions(userId);
    }

    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        String token = UUID.randomUUID().toString();
        user.setPasswordResetToken(token);
        user.setPasswordResetTokenExpiresAt(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        emailService.sendPasswordResetEmail(email, token);
    }

    public void resetPassword(PasswordResetConfirmRequest request) {
        User user = userRepository.findByPasswordResetToken(request.getToken())
                .orElseThrow(() -> new BadRequestException("Invalid password reset token"));

        if (user.getPasswordResetTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadRequestException("Password reset token has expired");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiresAt(null);
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate all sessions
        sessionRepository.deleteAllUserSessions(user.getId());
    }

    public void verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid email verification token"));

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        userRepository.save(user);
    }

    public void resendEmailVerification(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (user.getEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }

        String token = UUID.randomUUID().toString();
        user.setEmailVerificationToken(token);
        user.setEmailVerificationSentAt(LocalDateTime.now());
        userRepository.save(user);

        emailService.sendEmailVerification(email, token);
    }

    private UserDto convertToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .name(user.getName())
                .phone(user.getPhone())
                .role(user.getRole())
                .isActive(user.getIsActive())
                .isLocked(user.getIsLocked())
                .emailVerified(user.getEmailVerified())
                .lastLoginAt(user.getLastLoginAt())
                .lastLoginIp(user.getLastLoginIp())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

}
