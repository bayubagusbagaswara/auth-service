package com.custody.auth.controller;

import com.custody.auth.dto.ApiResponse;
import com.custody.auth.dto.request.RefreshTokenRequest;
import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/refresh")
    public ResponseEntity<@NonNull ApiResponse<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request
    ) {

        // Rotate refresh token and generate new access token.
        AuthResponse result = authService.refreshToken(
                request.refreshToken()
        );

        // Build the standardized API response.
        ApiResponse<AuthResponse> response =
                ApiResponse.<AuthResponse>builder()
                        .httpStatus(HttpStatus.OK.value())
                        .code("SUCCESS")
                        .message("Token refreshed successfully")
                        .data(result)
                        .build();

        return ResponseEntity.ok(response);
    }


    @PostMapping("/logout")
    public ResponseEntity<@NonNull ApiResponse<Void> >logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        // Revoke refresh token.
        authService.logout(request.refreshToken());

        // Build the standardized API response.
        ApiResponse<Void> response =
                ApiResponse.<Void>builder()
                        .httpStatus(HttpStatus.OK.value())
                        .code("SUCCESS")
                        .message("Logout successful")
                        .data(null)
                        .build();

        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    public ResponseEntity<@NonNull ApiResponse<UserResponse>> me(@AuthenticationPrincipal Jwt jwt) {
        // Extract username from the JWT subject.
        String username = jwt.getSubject();

        // Retrieve the current user from the database.
        UserResponse result =
                authService.getCurrentUser(username);

        // Build the standardized API response.
        ApiResponse<UserResponse> response =
                ApiResponse.<UserResponse>builder()
                        .httpStatus(HttpStatus.OK.value())
                        .code("SUCCESS")
                        .message("User retrieved successfully")
                        .data(result)
                        .build();

        return ResponseEntity.ok(response);
    }

}
