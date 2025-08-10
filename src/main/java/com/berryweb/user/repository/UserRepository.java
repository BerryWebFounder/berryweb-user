package com.berryweb.user.repository;

import com.berryweb.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameOrEmail(String username, String email);

    Optional<User> findByPasswordResetToken(String token);

    Optional<User> findByEmailVerificationToken(String token);

    Optional<User> findByUnlockToken(String token);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    List<User> findByRole(User.Role role);

    List<User> findByIsActive(Boolean isActive);

    List<User> findByIsLocked(Boolean isLocked);

    @Query("SELECT u FROM User u WHERE u.isLocked = true AND u.lockedAt < :cutoffTime")
    List<User> findLockedUsersOlderThan(@Param("cutoffTime") LocalDateTime cutoffTime);

    @Query("SELECT u FROM User u WHERE u.emailVerified = false AND u.emailVerificationSentAt < :cutoffTime")
    List<User> findUnverifiedUsersOlderThan(@Param("cutoffTime") LocalDateTime cutoffTime);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lastFailedLoginAt = null WHERE u.id = :userId")
    void resetFailedLoginAttempts(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE User u SET u.isLocked = false, u.lockedAt = null, u.unlockToken = null, u.unlockTokenExpiresAt = null WHERE u.id = :userId")
    void unlockUser(@Param("userId") Long userId);

    Page<User> findByNameContainingIgnoreCase(String name, Pageable pageable);

    Page<User> findByUsernameContainingIgnoreCase(String username, Pageable pageable);

    Page<User> findByEmailContainingIgnoreCase(String email, Pageable pageable);

}
