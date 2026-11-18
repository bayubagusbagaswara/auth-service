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

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    /**
     * Generate a signed JWT access token.
     */
    @Override
    public String generateAccessToken(
            UserEntity user,
            List<String> menus
    ) {

        // 1. Get the current UTC timestamp.
        Instant now = Instant.now(clock);

        // 2. Calculate the access token expiration time.
        Instant expiresAt = now.plus(
                jwtProperties.accessTokenExpiration()
        );

        // 3. Build JWT claims.
        JwtClaimsSet claims = JwtClaimsSet.builder()

                // Identify the trusted token issuer.
                .issuer(jwtProperties.issuer())

                // Set the authenticated username.
                .subject(user.getUsername())

                // Specify the intended audiences.
                .audience(jwtProperties.audience())

                // Set token creation time.
                .issuedAt(now)

                // Token becomes valid immediately.
                .notBefore(now)

                // Set the token expiration time.
                .expiresAt(expiresAt)

                // Assign a unique JWT identifier.
                .id(UUID.randomUUID().toString())

                // Add user information.
                .claim("fullName", user.getSurename())
                .claim("branchName", user.getBranchName())
                .claim("groupLevel", user.getGroupLevel())

                // Add authorized menus.
                .claim("menus", menus)

                .build();

        // 4. Configure JWT header using RS256.
        JwsHeader header = JwsHeader
                .with(SignatureAlgorithm.RS256)
                .keyId(jwtProperties.keyId())
                .build();

        // 5. Combine the JWT header and claims.
        JwtEncoderParameters parameters =
                JwtEncoderParameters.from(
                        header,
                        claims
                );

        // 6. Sign the JWT using the configured private key.
        return jwtEncoder
                .encode(parameters)
                .getTokenValue();
    }

}
