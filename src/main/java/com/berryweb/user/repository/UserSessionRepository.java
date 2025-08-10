package com.berryweb.user.repository;

import com.berryweb.user.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionToken(String sessionToken);

    List<UserSession> findByUserId(Long userId);

    List<UserSession> findByUserIdAndExpiresAtAfter(Long userId, LocalDateTime now);

    @Query("SELECT us FROM UserSession us WHERE us.expiresAt < :now")
    List<UserSession> findExpiredSessions(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM UserSession us WHERE us.expiresAt < :now")
    void deleteExpiredSessions(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM UserSession us WHERE us.user.id = :userId")
    void deleteAllUserSessions(@Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM UserSession us WHERE us.user.id = :userId AND us.sessionToken != :currentToken")
    void deleteOtherUserSessions(@Param("userId") Long userId, @Param("currentToken") String currentToken);

    long countByUserIdAndExpiresAtAfter(Long userId, LocalDateTime now);

    @Query("SELECT COUNT(us) FROM UserSession us WHERE us.expiresAt > :now")
    long countActiveSessions(@Param("now") LocalDateTime now);

}
