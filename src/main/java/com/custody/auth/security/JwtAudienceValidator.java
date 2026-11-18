package com.custody.auth.security;

import org.jspecify.annotations.NonNull;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Validates JWT audiences against trusted audiences.
 */
public class JwtAudienceValidator implements OAuth2TokenValidator<@NonNull Jwt> {

    private final List<String> allowedAudiences;

    public JwtAudienceValidator(List<String> allowedAudiences) {
        this.allowedAudiences = allowedAudiences;
    }

    @Override
    @NonNull
    public OAuth2TokenValidatorResult validate(Jwt jwt) {

        // Check whether the JWT contains at least one allowed audience.
        boolean valid = allowedAudiences != null
                && !allowedAudiences.isEmpty()
                && jwt.getAudience()
                .stream()
                .anyMatch(allowedAudiences::contains);

        if (valid) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(
                        "invalid_token",
                        "Invalid JWT audience",
                        null
                )
        );
    }
}
