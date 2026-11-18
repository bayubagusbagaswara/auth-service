package com.custody.auth.service.impl;

import com.custody.auth.config.JwtProperties;
import com.custody.auth.dto.response.RefreshTokenResponse;
import com.custody.auth.entity.RefreshTokenEntity;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.InvalidRefreshTokenException;
import com.custody.auth.repository.RefreshTokenRepository;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final int TOKEN_BYTES = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;
    private final TransactionTemplate transactionTemplate;

    @Override
    public RefreshTokenResponse createRefreshToken(String username) {
        if (username == null || username.isBlank()) {
            throw invalidToken();
        }

        return transactionTemplate.execute(status -> {

            // Retrieve the authenticated user.
            UserEntity user = userRepository
                    .findByUsername(username)
                    .orElseThrow(this::invalidToken);

            // Reject inactive users.
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
                throw invalidToken();
            }

            LocalDateTime now = nowUtc();

            // Read expiration from application.yml.
            LocalDateTime expiresAt = now.plus(
                    jwtProperties.refreshTokenExpiration()
            );

            String rawToken = generateSecureToken();

            // Store only the token hash.
            RefreshTokenEntity entity = new RefreshTokenEntity();
            entity.setUsername(user.getUsername());
            entity.setTokenHash(hashToken(rawToken));
            entity.setTokenFamilyId(UUID.randomUUID().toString());
            entity.setCreatedAt(now);
            entity.setExpiresAt(expiresAt);

            refreshTokenRepository.save(entity);

            return new RefreshTokenResponse(
                    rawToken,
                    user.getUsername(),
                    expiresAt
            );
        });
    }

    @Override
    public RefreshTokenResponse rotateRefreshToken(String refreshToken) {
        String tokenHash = hashToken(refreshToken);

        // Commit token changes before returning
        // an invalid-token exception.
        RefreshTokenResponse response =
                transactionTemplate.execute(status ->
                        rotateWithinTransaction(tokenHash)
                );

        if (response == null) {
            throw invalidToken();
        }

        return response;
    }

    /**
     * Perform token rotation inside a transaction.
     */
    private RefreshTokenResponse rotateWithinTransaction(
            String tokenHash
    ) {
        RefreshTokenEntity current = refreshTokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElse(null);

        if (current == null) {
            return null;
        }

        LocalDateTime now = nowUtc();

        // Detect reused or revoked tokens.
        if (current.getRevokedAt() != null) {
            revokeFamily(current.getTokenFamilyId(), now);
            return null;
        }

        // Reject expired tokens.
        if (!current.getExpiresAt().isAfter(now)) {
            current.setRevokedAt(now);
            return null;
        }

        // Verify the account is still active.
        UserEntity user = userRepository
                .findByUsername(current.getUsername())
                .orElse(null);

        if (user == null ||
                !"ACTIVE".equalsIgnoreCase(user.getStatus())) {

            revokeFamily(current.getTokenFamilyId(), now);
            return null;
        }

        String newRawToken = generateSecureToken();

        // Preserve the initial session expiration.
        LocalDateTime expiresAt = current.getExpiresAt();

        RefreshTokenEntity replacement =
                new RefreshTokenEntity();

        replacement.setUsername(current.getUsername());
        replacement.setTokenHash(hashToken(newRawToken));
        replacement.setTokenFamilyId(current.getTokenFamilyId());
        replacement.setCreatedAt(now);
        replacement.setExpiresAt(expiresAt);

        replacement = refreshTokenRepository
                .saveAndFlush(replacement);

        // Mark the previous token as revoked.
        current.setRevokedAt(now);
        current.setReplacedByTokenId(replacement.getId());

        return new RefreshTokenResponse(
                newRawToken,
                current.getUsername(),
                expiresAt
        );
    }

    /**
     * Revoke the entire refresh token session.
     */
    @Override
    public void revokeRefreshToken(String refreshToken) {

        String tokenHash = hashToken(refreshToken);

        transactionTemplate.executeWithoutResult(status -> {

            RefreshTokenEntity current = refreshTokenRepository
                    .findByTokenHashForUpdate(tokenHash)
                    .orElse(null);

            if (current != null) {
                revokeFamily(
                        current.getTokenFamilyId(),
                        nowUtc()
                );
            }
        });
    }

    /**
     * Revoke all active tokens in a token family.
     *
     * Must be executed inside a transaction.
     */
    private void revokeFamily(
            String familyId,
            LocalDateTime revokedAt
    ) {
        List<RefreshTokenEntity> tokens =
                refreshTokenRepository.findByTokenFamilyId(
                        familyId
                );

        for (RefreshTokenEntity token : tokens) {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(revokedAt);
            }
        }
    }

    /**
     * Generate a cryptographically secure token.
     */
    private String generateSecureToken() {

        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    /**
     * Hash a refresh token using SHA-256.
     */
    private String hashToken(String rawToken) {

        if (rawToken == null || rawToken.isBlank()) {
            throw invalidToken();
        }

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    rawToken.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is unavailable", e
            );
        }
    }

    /**
     * Return current UTC timestamp.
     */
    private LocalDateTime nowUtc() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    /**
     * Create a generic invalid token exception.
     */
    private InvalidRefreshTokenException invalidToken() {
        return new InvalidRefreshTokenException(
                "Invalid or expired refresh token"
        );
    }
}
