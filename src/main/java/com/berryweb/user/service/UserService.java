package com.berryweb.user.service;

import com.berryweb.user.dto.*;
import com.berryweb.user.entity.User;
import com.berryweb.user.entity.UserRoleHistory;
import com.berryweb.user.entity.UserSession;
import com.berryweb.user.exception.ResourceNotFoundException;
import com.berryweb.user.repository.UserRepository;
import com.berryweb.user.repository.UserRoleHistoryRepository;
import com.berryweb.user.repository.UserSessionRepository;
import com.berryweb.user.security.CustomUserPrincipal;
import jakarta.ws.rs.BadRequestException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final UserRoleHistoryRepository roleHistoryRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public Page<UserDto> getAllUsers(int page, int size, String sortBy) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy));
        return userRepository.findAll(pageable).map(this::convertToUserDto);
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(Long id) {
        User user = findUserById(id);
        return convertToUserDto(user);
    }

    @Transactional(readOnly = true)
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();
        return getUserById(principal.getId());
    }

    public UserDto createUser(UserCreateRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username is already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email is already registered");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .phone(request.getPhone())
                .role(request.getRole() != null ? request.getRole() : User.Role.USER)
                .isActive(request.getIsActive() != null ? request.getIsActive() : true)
                .emailVerified(request.getEmailVerified() != null ? request.getEmailVerified() : false)
                .build();

        user = userRepository.save(user);
        return convertToUserDto(user);
    }

    public UserDto updateUser(Long id, UserUpdateRequest request) {
        User user = findUserById(id);
        User.Role oldRole = user.getRole();

        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new BadRequestException("Email is already registered");
            }
            user.setEmail(request.getEmail());
            user.setEmailVerified(false); // Require re-verification
        }

        if (request.getName() != null) {
            user.setName(request.getName());
        }

        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }

        if (request.getIsActive() != null) {
            user.setIsActive(request.getIsActive());
        }

        if (request.getIsLocked() != null) {
            if (request.getIsLocked()) {
                user.lockAccount();
            } else {
                user.unlockAccount();
            }
        }

        // Handle role change
        if (request.getRole() != null && !request.getRole().equals(oldRole)) {
            user.setRole(request.getRole());

            // Record role change history
            CustomUserPrincipal principal = getCurrentUserPrincipal();
            UserRoleHistory roleHistory = UserRoleHistory.of(
                    user, oldRole, request.getRole(), principal.getId(), request.getReason()
            );
            roleHistoryRepository.save(roleHistory);
        }

        user = userRepository.save(user);
        return convertToUserDto(user);
    }

    public void deleteUser(Long id) {
        User user = findUserById(id);
        userRepository.delete(user);
    }

    public void changePassword(Long userId, PasswordChangeRequest request) {
        User user = findUserById(userId);

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate all sessions except current one (if applicable)
        // This forces re-login on other devices
        sessionRepository.deleteAllUserSessions(userId);
    }

    @Transactional(readOnly = true)
    public List<UserRoleHistoryDto> getUserRoleHistory(Long userId) {
        return roleHistoryRepository.findByUserIdOrderByChangedAtDesc(userId)
                .stream()
                .map(this::convertToRoleHistoryDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<UserSessionDto> getUserSessions(Long userId) {
        List<UserSession> sessions = sessionRepository.findByUserIdAndExpiresAtAfter(userId, LocalDateTime.now());
        return sessions.stream()
                .map(session -> convertToSessionDto(session, false)) // Determine if current session
                .collect(Collectors.toList());
    }

    private User findUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    private CustomUserPrincipal getCurrentUserPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserPrincipal) authentication.getPrincipal();
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

    private UserRoleHistoryDto convertToRoleHistoryDto(UserRoleHistory history) {
        // Get username of the user who made the change
        String changedByUsername = userRepository.findById(history.getChangedBy())
                .map(User::getUsername)
                .orElse("Unknown");

        return UserRoleHistoryDto.builder()
                .id(history.getId())
                .oldRole(history.getOldRole())
                .newRole(history.getNewRole())
                .changedByUsername(changedByUsername)
                .reason(history.getReason())
                .changedAt(history.getChangedAt())
                .build();
    }

    private UserSessionDto convertToSessionDto(UserSession session, boolean isCurrent) {
        return UserSessionDto.builder()
                .id(session.getId())
                .ipAddress(session.getIpAddress())
                .userAgent(session.getUserAgent())
                .expiresAt(session.getExpiresAt())
                .createdAt(session.getCreatedAt())
                .isActive(session.isValid())
                .isCurrent(isCurrent)
                .build();
    }

}
