package com.custody.auth.security;

import com.custody.auth.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Handles authorization failures with a standardized JSON response.
 */
@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(
            @NonNull HttpServletRequest request,
            HttpServletResponse response,
            @NonNull AccessDeniedException accessDeniedException
    ) throws IOException {

        // Set HTTP 403 status.
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // Set JSON content type.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Build standardized API response.
        ApiResponse<Void> apiResponse =
                ApiResponse.<Void>builder()
                        .httpStatus(HttpStatus.FORBIDDEN.value())
                        .code("ACCESS_DENIED")
                        .message("You do not have permission to access this resource")
                        .data(null)
                        .build();

        // Write JSON response directly.
        objectMapper.writeValue(
                response.getOutputStream(),
                apiResponse
        );
    }

}
