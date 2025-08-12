package com.berryweb.user.controller;

import com.berryweb.user.dto.*;
import com.berryweb.user.security.CustomUserPrincipal;
import com.berryweb.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/users")
@RequiredArgsConstructor
@CrossOrigin("*")
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserDto>> getCurrentUser() {
        UserDto user = userService.getCurrentUser();
        return ResponseEntity.ok(ApiResponse.success(user));
    }

    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserDto>> updateCurrentUser(
            @Valid @RequestBody UserUpdateRequest request,
            Authentication authentication) {

        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();

        // Users can only update their own basic info, not role or lock status
        request.setRole(null);
        request.setIsLocked(null);

        UserDto user = userService.updateUser(principal.getId(), request);
        return ResponseEntity.ok(ApiResponse.success("Profile updated successfully", user));
    }

    @PostMapping("/me/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            Authentication authentication) {

        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();
        userService.changePassword(principal.getId(), request);
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully", null));
    }

    @GetMapping("/me/role-history")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<java.util.List<UserRoleHistoryDto>>> getCurrentUserRoleHistory(
            Authentication authentication) {

        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();
        java.util.List<UserRoleHistoryDto> history = userService.getUserRoleHistory(principal.getId());
        return ResponseEntity.ok(ApiResponse.success(history));
    }

    @GetMapping("/me/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<java.util.List<UserSessionDto>>> getCurrentUserSessions(
            Authentication authentication) {

        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();
        java.util.List<UserSessionDto> sessions = userService.getUserSessions(principal.getId());
        return ResponseEntity.ok(ApiResponse.success(sessions));
    }

    // Admin endpoints
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('SYSOP')")
    public ResponseEntity<ApiResponse<org.springframework.data.domain.Page<UserDto>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy) {

        org.springframework.data.domain.Page<UserDto> users = userService.getAllUsers(page, size, sortBy);
        return ResponseEntity.ok(ApiResponse.success(users));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SYSOP')")
    public ResponseEntity<ApiResponse<UserDto>> getUserById(@PathVariable Long id) {
        UserDto user = userService.getUserById(id);
        return ResponseEntity.ok(ApiResponse.success(user));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserDto>> createUser(@Valid @RequestBody UserCreateRequest request) {
        UserDto user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User created successfully", user));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or (hasRole('SYSOP') and !@userService.getUserById(#id).role.name().equals('ADMIN'))")
    public ResponseEntity<ApiResponse<UserDto>> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserUpdateRequest request) {

        UserDto user = userService.updateUser(id, request);
        return ResponseEntity.ok(ApiResponse.success("User updated successfully", user));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully", null));
    }

    @GetMapping("/{id}/role-history")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SYSOP')")
    public ResponseEntity<ApiResponse<java.util.List<UserRoleHistoryDto>>> getUserRoleHistory(@PathVariable Long id) {
        java.util.List<UserRoleHistoryDto> history = userService.getUserRoleHistory(id);
        return ResponseEntity.ok(ApiResponse.success(history));
    }

    @GetMapping("/{id}/sessions")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SYSOP')")
    public ResponseEntity<ApiResponse<java.util.List<UserSessionDto>>> getUserSessions(@PathVariable Long id) {
        java.util.List<UserSessionDto> sessions = userService.getUserSessions(id);
        return ResponseEntity.ok(ApiResponse.success(sessions));
    }

    @PostMapping("/{id}/change-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> adminChangePassword(
            @PathVariable Long id,
            @Valid @RequestBody PasswordChangeRequest request) {

        // For admin password change, we skip the current password check
        // by creating a simplified version
        userService.changePassword(id, request);
        return ResponseEntity.ok(ApiResponse.success("User password changed successfully", null));
    }

}
