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
     * Rotate a refresh token and generate a new JWT.
     *
     * Refresh token persistence is managed by
     * RefreshTokenServiceImpl.
     */
    @Override
    public AuthResponse refreshToken(String refreshToken) {

        // 1. Validate and rotate the refresh token.
        // The service manages its own transaction.
        RefreshTokenResponse rotatedToken =
                refreshTokenService.rotateRefreshToken(refreshToken);

        // 2. Retrieve the current user.
        UserEntity user = userRepository
                .findByUsername(rotatedToken.username())
                .orElseThrow(this::invalidRefreshToken);

        // 3. Verify that the user is still active.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidRefreshToken();
        }

        // 4. Retrieve the latest user information
        // and menu permissions.
        UserResponse userResponse =
                userService.getUserByUsername(user.getUsername());

        // 5. Generate a new signed JWT access token.
        String accessToken = jwtService.generateAccessToken(
                user,
                userResponse.menus()
        );

        // 6. Build the authentication response.
        return new AuthResponse(
                accessToken,
                rotatedToken.refreshToken(),
                userResponse
        );
    }

    /**
     * Revoke a refresh token session.
     */
    @Override
    public void logout(String refreshToken) {

        // Revoke the refresh token family.
        refreshTokenService.revokeRefreshToken(refreshToken);
    }

    /**
     * Retrieve the currently authenticated user's information.
     */
    @Override
    public UserResponse getCurrentUser(String username) {

        // 1. Find the registered user.
        UserEntity user = userRepository
                .findByUsername(username)
                .orElseThrow(this::invalidRefreshToken);

        // 2. Verify that the account is active.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidRefreshToken();
        }

        // 3. Return the current user information
        // and menu permissions.
        return userService.getUserByUsername(username);
    }

    /**
     * Create a generic invalid session exception.
     */
    private InvalidRefreshTokenException invalidRefreshToken() {

        return new InvalidRefreshTokenException(
                "Invalid or expired authentication session"
        );
    }

}