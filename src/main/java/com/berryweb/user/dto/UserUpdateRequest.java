package com.berryweb.user.dto;

import com.berryweb.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserUpdateRequest {

    private String email;
    private String name;
    private String phone;
    private User.Role role;
    private Boolean isActive;
    private Boolean isLocked;
    private String reason;

}
