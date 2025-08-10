package com.berryweb.user.repository;

import com.berryweb.user.entity.UserRoleHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRoleHistoryRepository extends JpaRepository<UserRoleHistory, Long> {

    List<UserRoleHistory> findByUserIdOrderByChangedAtDesc(Long userId);

    List<UserRoleHistory> findByChangedByOrderByChangedAtDesc(Long changedBy);

    Page<UserRoleHistory> findByUserIdOrderByChangedAtDesc(Long userId, Pageable pageable);

    @Query("SELECT urh FROM UserRoleHistory urh WHERE urh.changedAt BETWEEN :startDate AND :endDate ORDER BY urh.changedAt DESC")
    List<UserRoleHistory> findRoleChangesInPeriod(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    Optional<UserRoleHistory> findTopByUserIdOrderByChangedAtDesc(Long userId);

}
