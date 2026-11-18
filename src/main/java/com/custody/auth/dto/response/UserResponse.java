package com.custody.auth.dto.response;

import java.time.LocalDateTime;
import java.util.List;

public record UserResponse(
        String username,
        String fullName,
        String branchName,
        String status,
        String groupLevel,
        LocalDateTime lastLogin,
        List<String> menus
) {

}
