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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TransactionTemplate transactionTemplate;

    public AuthServiceImpl(
            UserRepository userRepository,
            UserService userService,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            PlatformTransactionManager transactionManager
    ) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.transactionTemplate =
                new TransactionTemplate(transactionManager);
    }

    /**
     * Rotate refresh token and issue a new JWT
     * within a single database transaction.
     */
    @Override
    public AuthResponse refreshToken(String refreshToken) {

        AuthResponse result = transactionTemplate.execute(status -> {

            RefreshTokenResponse rotatedToken;

            try {
                // Validate the existing refresh token,
                // verify user status and rotate it.
                rotatedToken = refreshTokenService
                        .rotateRefreshToken(refreshToken);

            } catch (InvalidRefreshTokenException ex) {

                // Return normally so security-related
                // revocations can be committed.
                return null;
            }

            // Retrieve the current user.
            UserEntity user = userRepository
                    .findByUsername(rotatedToken.username())
                    .orElseThrow(this::invalidRefreshToken);

            // Recheck user status before issuing the JWT.
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
                throw invalidRefreshToken();
            }

            // Retrieve the latest user profile and permissions.
            UserResponse userResponse =
                    userService.getUserByUsername(user.getUsername());

            // Generate a new signed JWT access token.
            String accessToken = jwtService.generateAccessToken(
                    user,
                    userResponse.menus()
            );

            // Return the result after database operations.
            return new AuthResponse(
                    accessToken,
                    rotatedToken.refreshToken(),
                    userResponse
            );
        });

        // Reject unsuccessful refresh attempts.
        if (result == null) {
            throw invalidRefreshToken();
        }

        return result;
    }

    /**
     * Revoke the refresh token session.
     */
    @Override
    public void logout(String refreshToken) {

        refreshTokenService.revokeRefreshToken(refreshToken);
    }

    /**
     * Retrieve information about the authenticated user.
     */
    @Override
    public UserResponse getCurrentUser(String username) {

        // Verify that the user is still registered.
        UserEntity user = userRepository
                .findByUsername(username)
                .orElseThrow(this::invalidRefreshToken);

        // Reject inactive user accounts.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidRefreshToken();
        }

        // Retrieve user information and current permissions.
        return userService.getUserByUsername(username);
    }

    /**
     * Return a generic invalid session exception.
     */
    private InvalidRefreshTokenException invalidRefreshToken() {

        return new InvalidRefreshTokenException(
                "Invalid or expired authentication session"
        );
    }

}
