package com.custody.auth.service.impl;

import com.custody.auth.dto.request.LoginRequest;
import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.JwtService;
import com.custody.auth.service.LoginService;
import com.custody.auth.service.RefreshTokenService;
import com.custody.auth.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class LoginServiceImpl implements LoginService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final String testUsername;

    public LoginServiceImpl(
            UserRepository userRepository,
            UserService userService,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            @Value("${app.auth.test-username}") String testUsername
    ) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.testUsername = testUsername;
    }

    /**
     * Authenticate a local test user using username only.
     *
     * This method must never be enabled in SIT or production.
     */
    @Override
    public AuthResponse login(LoginRequest request) {

        // 1. Retrieve username from request.
        String username = request.username();

        // 2. Allow only the configured local test account.
        if (!testUsername.equals(username)) {
            throw new InvalidCredentialsException(
                    "Invalid authentication credentials"
            );
        }

        // 3. Find user in CSAUSERS.
        UserEntity user = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "Invalid authentication credentials"
                        )
                );

        // 4. Validate user status.
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw new InvalidCredentialsException(
                    "Invalid authentication credentials"
            );
        }

        // 5. Retrieve user information and menu permissions.
        // UserService already reads CSAMENUACCESS based on groupLevel.
        UserResponse userResponse =
                userService.getUserByUsername(username);

        // 6. Generate JWT access token with user claims.
        String accessToken = jwtService.generateAccessToken(
                user,
                userResponse.menus()
        );

        // 7. Create refresh token and persist its hash.
        RefreshTokenResponse refreshTokenResponse =
                refreshTokenService.createRefreshToken(username);

        // 8. Build authentication response.
        return new AuthResponse(
                accessToken,
                refreshTokenResponse.refreshToken(),
                userResponse
        );
    }
}
