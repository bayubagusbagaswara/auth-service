package com.custody.auth.service.impl;

import com.custody.auth.config.JwtProperties;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;

    /**
     * Generate a JWT access token.
     *
     * Must only be invoked after successful
     * authentication and account validation.
     */
    @Override
    public String generateAccessToken(
            UserEntity user,
            List<String> menus
    ) {

        // Current timestamp in UTC.
        Instant now = Instant.now();

        // Read access token expiration from application.yml.
        Instant expiresAt = now.plus(
                jwtProperties.accessTokenExpiration()
        );

        // Define JWT claims.
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .subject(user.getUsername())
                .audience(jwtProperties.audience())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("fullName", user.getSurename())
                .claim("branchName", user.getBranchName())
                .claim("groupLevel", user.getGroupLevel())
                .claim("menus", menus)
                .build();

        // Define JWT header using RSA SHA-256.
        JwsHeader header = JwsHeader
                .with(SignatureAlgorithm.RS256)
                .keyId(jwtProperties.keyId())
                .build();

        // Sign and encode the access token.
        return jwtEncoder.encode(
                JwtEncoderParameters.from(header, claims)
        ).getTokenValue();
    }
}
