package com.custody.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String issuer,
        String keyId,
        String privateKey,
        String publicKey,
        Duration accessTokenExpiration,
        Duration refreshTokenExpiration,
        List<String> audience
) {

}
