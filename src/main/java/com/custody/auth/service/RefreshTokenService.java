package com.custody.auth.service;

import com.custody.auth.dto.response.RefreshTokenResponse;

public interface RefreshTokenService {

    RefreshTokenResponse createRefreshToken(String username);

    RefreshTokenResponse rotateRefreshToken(String refreshToken);

    void revokeRefreshToken(String refreshToken);

}
