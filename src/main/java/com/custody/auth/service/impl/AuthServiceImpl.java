package com.custody.auth.service.impl;

import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.InvalidRefreshTokenException;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.AuthService;
import com.custody.auth.service.JwtService;
import com.custody.auth.service.RefreshTokenService;
import com.custody.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Rotate the refresh token and generate a new JWT.
     * POST /api/v1/auth/refresh
     */
    @Override
    public AuthResponse refreshToken(String refreshToken) {

        // 1. Rotate the refresh token.
        // The previous token is revoked after rotation.
        RefreshTokenResponse rotatedToken =
                refreshTokenService.rotateRefreshToken(refreshToken);

        // 2. Retrieve the user associated with the refresh token.
        UserEntity user = userRepository
                .findByUsername(rotatedToken.username())
                .orElseThrow(this::invalidRefreshToken);

        // 3. Check whether the user is still active.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {

            // Revoke the newly rotated token family
            // to prevent further refresh attempts.
            refreshTokenService.revokeRefreshToken(
                    rotatedToken.refreshToken()
            );

            throw invalidRefreshToken();
        }

        // 4. Retrieve current user information and menu permissions.
        UserResponse userResponse =
                userService.getUserByUsername(user.getUsername());

        // 5. Generate a new access token using current permissions.
        String accessToken = jwtService.generateAccessToken(
                user,
                userResponse.menus()
        );

        // 6. Return the new access token and rotated refresh token.
        return new AuthResponse(
                accessToken,
                rotatedToken.refreshToken(),
                userResponse
        );
    }

    /**
     * Revoke the refresh token session.
     * POST /api/v1/auth/logout
     */
    @Override
    public void logout(String refreshToken) {

        // Revoke the refresh token family.
        refreshTokenService.revokeRefreshToken(refreshToken);
    }

    /**
     * Get current authenticated user information.
     * GET /api/v1/auth/me
     */
    @Override
    public UserResponse getCurrentUser(String username) {
        // Retrieve user from CSAUSERS and its menu permissions.
        return userService.getUserByUsername(username);
    }

    /**
     * Return a generic error for invalid refresh sessions.
     */
    private InvalidRefreshTokenException invalidRefreshToken() {

        return new InvalidRefreshTokenException(
                "Invalid or expired refresh token"
        );
    }

}
