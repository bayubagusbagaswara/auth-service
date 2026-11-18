package com.custody.auth.dto.response;

import java.time.LocalDateTime;

public record RefreshTokenResponse(
        String refreshToken,
        String username,
        LocalDateTime expiresAt
) {

}
