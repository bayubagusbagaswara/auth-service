package com.custody.auth.exception;

import com.custody.auth.dto.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

//    @ExceptionHandler(InvalidCredentialsException.class)
//    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(
//            InvalidCredentialsException ex
//    ) {
//
//        return buildError(
//                HttpStatus.UNAUTHORIZED,
//                "AUTHENTICATION_FAILED",
//                "Invalid authentication credentials"
//        );
//    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex
    ) {

        return buildError(
                HttpStatus.UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Invalid or expired refresh token"
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotFound(
            ResourceNotFoundException ex
    ) {

        return buildError(
                HttpStatus.NOT_FOUND,
                "USER_NOT_FOUND",
                ex.getMessage()
        );
    }

    /**
     * Build a standardized error response.
     */
    private ResponseEntity<ApiResponse<Void>> buildError(
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
