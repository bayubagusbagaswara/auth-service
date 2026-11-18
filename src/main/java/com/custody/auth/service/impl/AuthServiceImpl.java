package com.custody.auth.service.impl;

import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.InvalidRefreshTokenException;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final MenuAccessService menuAccessService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Rotate a refresh token and issue a new access token.
     */
    @Override
    public AuthResponse refreshToken(String refreshToken) {

        // Validate and rotate the existing refresh token.
        RefreshTokenResponse rotatedToken =
                refreshTokenService.rotateRefreshToken(
                        refreshToken
                );

        String username = rotatedToken.username();

        // Retrieve the user.
        UserEntity user = userRepository
                .findByUsername(username)
                .orElseThrow(this::invalidToken);

        // Reject users who are no longer active.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidToken();
        }

        // Retrieve current menu permissions.
        List<String> menus = menuAccessService
                .getMenusByGroupName(user.getGroupLevel());

        // Generate a new JWT access token.
        String accessToken = jwtService
                .generateAccessToken(user, menus);

        // Retrieve the user's response information.
        UserResponse userResponse = userService
                .getUserByUsername(username);

        // Return both tokens and user information.
        return new AuthResponse(
                accessToken,
                rotatedToken.refreshToken(),
                userResponse
        );
    }

    /**
     * Revoke the refresh token session.
     */
    @Override
    public void logout(String refreshToken) {

        refreshTokenService.revokeRefreshToken(
                refreshToken
        );
    }

    /**
     * Retrieve the current authenticated user's information.
     */
    @Override
    public UserResponse getCurrentUser(String username) {

        return userService.getUserByUsername(username);
    }

    private InvalidRefreshTokenException invalidToken() {
        return new InvalidRefreshTokenException(
                "Invalid or expired refresh token"
        );
    }
}
