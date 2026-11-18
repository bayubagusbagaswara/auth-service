package com.custody.auth.controller;

import com.custody.auth.dto.ApiResponse;
import com.custody.auth.dto.request.LoginRequest;
import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.service.LoginService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class LoginController {

    private final LoginService localLoginService;

    @PostMapping("/login")
    public ResponseEntity<@NonNull ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request
    ) {

        AuthResponse result = localLoginService.login(request);

        ApiResponse<AuthResponse> response = ApiResponse.<AuthResponse>builder()
                .httpStatus(HttpStatus.OK.value())
                .code("SUCCESS")
                .message("Login successful")
                .data(result)
                .build();

        return ResponseEntity.ok(response);
    }
}
