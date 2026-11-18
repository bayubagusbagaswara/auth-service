package com.custody.auth.service.impl;

import com.custody.auth.dto.request.LoginRequest;
import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.InvalidCredentialsException;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.JwtService;
import com.custody.auth.service.LoginService;
import com.custody.auth.service.RefreshTokenService;
import com.custody.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public AuthResponse login(LoginRequest request) {

        // 1. Retrieve username from request.
        String username = request.username().trim();

        // 2. Find registered user in CSAUSERS.
        UserEntity user = userRepository
                .findByUsername(username)
                .orElseThrow(this::invalidCredentials);

        // 3. Verify user status.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidCredentials();
        }

        // 4. Retrieve user information and menu permissions.
        UserResponse userResponse = userService.getUserByUsername(username);

        // 5. Generate JWT access token.
        String accessToken = jwtService.generateAccessToken(
                user,
                userResponse.menus()
        );

        // 6. Generate and persist refresh token.
        RefreshTokenResponse refreshTokenResponse =
                refreshTokenService.createRefreshToken(username);

        // 7. Build authentication response.
        return new AuthResponse(
                accessToken,
                refreshTokenResponse.refreshToken(),
                userResponse
        );
    }

    private InvalidCredentialsException invalidCredentials() {
        return new InvalidCredentialsException(
                "Invalid authentication credentials"
        );
    }

}
