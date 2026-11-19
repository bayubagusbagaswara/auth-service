package com.custody.auth.exception;

import com.custody.auth.dto.ApiResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handle invalid login credentials.
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<@NonNull ApiResponse<Void>> handleInvalidCredentials(
            InvalidCredentialsException ex
    ) {

        return buildError(
                HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Invalid authentication credentials"
        );
    }

    /**
     * Handle invalid or expired refresh tokens.
     */
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<@NonNull ApiResponse<Void>> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex
    ) {

        return buildError(
                HttpStatus.UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Invalid or expired authentication session"
        );
    }

    /**
     * Handle resources that cannot be found.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<@NonNull ApiResponse<Void>> handleNotFound(
            ResourceNotFoundException ex
    ) {

        return buildError(
                HttpStatus.NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                ex.getMessage()
        );
    }

    /**
     * Handle request body validation errors.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<@NonNull ApiResponse<Void>> handleValidationError(
            MethodArgumentNotValidException ex
    ) {

        return buildError(
                HttpStatus.BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid request parameters"
        );
    }

    /**
     * Handle malformed or unreadable JSON request bodies.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<@NonNull ApiResponse<Void>> handleMalformedRequest(
            HttpMessageNotReadableException ex
    ) {

        return buildError(
                HttpStatus.BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                "Invalid or missing request body"
        );
    }

    /**
     * Build a standardized API error response.
     */
    private ResponseEntity<@NonNull ApiResponse<Void>> buildError(
            HttpStatus status,
            String code,
            String message
    ) {

        ApiResponse<Void> response = ApiResponse
                .<Void>builder()
                .httpStatus(status.value())
                .code(code)
                .message(message)
                .data(null)
                .build();

        return ResponseEntity
                .status(status)
                .body(response);
    }

}
