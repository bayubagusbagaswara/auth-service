package com.custody.auth.controller;

import com.custody.auth.dto.request.RefreshTokenRequest;
import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Refresh an access token and rotate
     * the existing refresh token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {

        return ResponseEntity.ok(
                authService.refreshToken(
                        request.refreshToken()
                )
        );
    }

    /**
     * Revoke the refresh token session.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {

        authService.logout(request.refreshToken());

        return ResponseEntity.noContent().build();
    }

    /**
     * Retrieve the current authenticated user.
     *
     * The username comes from the validated JWT,
     * not from a client-supplied username parameter.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(
                authService.getCurrentUser(jwt.getSubject())
        );
    }

}
