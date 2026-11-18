package com.custody.auth.security;

import com.custody.auth.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Handles authentication failures with a standardized JSON response.
 */
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            @NonNull HttpServletRequest request,
            HttpServletResponse response,
            @NonNull AuthenticationException authException
    ) throws IOException {

        // Set HTTP 401 status.
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        // Set JSON content type.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Indicate that bearer authentication is required.
        response.setHeader("WWW-Authenticate", "Bearer");

        // Build standardized API response.
        ApiResponse<Void> apiResponse =
                ApiResponse.<Void>builder()
                        .httpStatus(HttpStatus.UNAUTHORIZED.value())
                        .code("UNAUTHORIZED")
                        .message("Authentication is required or token is invalid")
                        .data(null)
                        .build();

        // Write JSON response directly.
        objectMapper.writeValue(
                response.getOutputStream(),
                apiResponse
        );
    }

}
