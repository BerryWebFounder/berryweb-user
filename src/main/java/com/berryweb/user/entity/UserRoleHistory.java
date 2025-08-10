package com.berryweb.user.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_role_history")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserRoleHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "old_role")
    private User.Role oldRole;

    @Enumerated(EnumType.STRING)
    @Column(name = "new_role", nullable = false)
    private User.Role newRole;

    @Column(name = "changed_by", nullable = false)
    private Long changedBy;

    @CreationTimestamp
    @Column(name = "changed_at", nullable = false, updatable = false)
    private LocalDateTime changedAt;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    // Static factory method for creating role history
    public static UserRoleHistory of(User user, User.Role oldRole, User.Role newRole, Long changedBy, String reason) {
        return UserRoleHistory.builder()
                .user(user)
                .oldRole(oldRole)
                .newRole(newRole)
                .changedBy(changedBy)
                .reason(reason)
                .build();
    }

}
