package com.custody.auth.service.impl;

import com.custody.auth.config.JwtProperties;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.entity.RefreshTokenEntity;
import com.custody.auth.exception.InvalidRefreshTokenException;
import com.custody.auth.repository.RefreshTokenRepository;
import com.custody.auth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final TransactionTemplate transactionTemplate;
    private final Clock clock;

    public RefreshTokenServiceImpl(
            RefreshTokenRepository refreshTokenRepository,
            JwtProperties jwtProperties,
            PlatformTransactionManager transactionManager,
            Clock clock
    ) {

        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
        this.transactionTemplate =
                new TransactionTemplate(transactionManager);
        this.clock = clock;
    }

    /**
     * Create a new refresh token family for a user.
     */
    @Override
    public RefreshTokenResponse createRefreshToken(String username) {

        return transactionTemplate.execute(status -> {

            String familyId = UUID.randomUUID().toString();

            return createToken(username, familyId);
        });
    }

    /**
     * Rotate an active refresh token.
     * Reusing a previously rotated token revokes
     * all tokens belonging to the same family.
     */
    @Override
    public RefreshTokenResponse rotateRefreshToken(
            String refreshToken
    ) {

        String tokenHash = hashToken(refreshToken);

        // Return a result instead of throwing inside
        // the transaction when revocation must be committed.
        RotationResult result = transactionTemplate.execute(status -> {

            RefreshTokenEntity currentToken =
                    refreshTokenRepository
                            .findByTokenHashForUpdate(tokenHash)
                            .orElseThrow(this::invalidToken);

            LocalDateTime now = LocalDateTime.now(clock);

            // Detect reuse of a previously revoked token.
            if (currentToken.getRevokedAt() != null) {

                // A previously rotated token being reused
                // is treated as a possible session compromise.
                if (currentToken.getReplacedByTokenId() != null) {
                    revokeFamily(
                            currentToken.getTokenFamilyId(),
                            now
                    );
                }

                return new RotationResult(null, false);
            }

            // Reject expired refresh tokens.
            if (!currentToken.getExpiresAt().isAfter(now)) {
                return new RotationResult(null, false);
            }

            // Create the replacement token in the same family.
            RefreshTokenResponse replacement = createToken(
                    currentToken.getUsername(),
                    currentToken.getTokenFamilyId()
            );

            // Find the newly persisted replacement by its hash.
            RefreshTokenEntity replacementEntity =
                    refreshTokenRepository.findByTokenHash(
                            hashToken(replacement.refreshToken())
                    ).orElseThrow(this::invalidToken);

            // Revoke the previous token and link its replacement.
            currentToken.setRevokedAt(now);
            currentToken.setReplacedByTokenId(
                    replacementEntity.getId()
            );

            refreshTokenRepository.save(currentToken);

            return new RotationResult(replacement, true);
        });

        if (result == null || !result.valid()) {
            throw invalidToken();
        }

        return result.response();
    }

    /**
     * Revoke a refresh token family during logout.
     */
    @Override
    public void revokeRefreshToken(String refreshToken) {

        String tokenHash = hashToken(refreshToken);

        transactionTemplate.executeWithoutResult(status -> {

            RefreshTokenEntity currentToken =
                    refreshTokenRepository
                            .findByTokenHashForUpdate(tokenHash)
                            .orElseThrow(this::invalidToken);

            revokeFamily(
                    currentToken.getTokenFamilyId(),
                    LocalDateTime.now(clock)
            );
        });
    }

    /**
     * Generate and persist a new opaque refresh token.
     */
    private RefreshTokenResponse createToken(
            String username,
            String familyId
    ) {

        String rawToken = generateToken();
        LocalDateTime now = LocalDateTime.now(clock);

        LocalDateTime expiresAt = now.plus(
                jwtProperties.refreshTokenExpiration()
        );

        RefreshTokenEntity entity = new RefreshTokenEntity();

        entity.setUsername(username);
        entity.setTokenHash(hashToken(rawToken));
        entity.setTokenFamilyId(familyId);
        entity.setCreatedAt(now);
        entity.setExpiresAt(expiresAt);
        entity.setRevokedAt(null);
        entity.setReplacedByTokenId(null);

        refreshTokenRepository.saveAndFlush(entity);

        // Only return the raw token to the client.
        // The database stores its hash.
        return new RefreshTokenResponse(
                rawToken,
                username,
                expiresAt
        );
    }

    /**
     * Revoke every active token in the given family.
     */
    private void revokeFamily(
            String familyId,
            LocalDateTime revokedAt
    ) {

        List<RefreshTokenEntity> tokens =
                refreshTokenRepository.findByTokenFamilyId(familyId);

        for (RefreshTokenEntity token : tokens) {

            if (token.getRevokedAt() == null) {
                token.setRevokedAt(revokedAt);
            }
        }

        refreshTokenRepository.saveAll(tokens);
    }

    /**
     * Generate a cryptographically secure random token.
     */
    private String generateToken() {

        byte[] randomBytes = new byte[32];

        SECURE_RANDOM.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

    /**
     * Hash a refresh token using SHA-256.
     */
    private String hashToken(String refreshToken) {

        if (refreshToken == null || refreshToken.isBlank()) {
            throw invalidToken();
        }

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    refreshToken.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is unavailable",
                    ex
            );
        }
    }

    private InvalidRefreshTokenException invalidToken() {
        return new InvalidRefreshTokenException(
                "Invalid or expired refresh token"
        );
    }

    private record RotationResult(
            RefreshTokenResponse response,
            boolean valid
    ) {
    }

}
