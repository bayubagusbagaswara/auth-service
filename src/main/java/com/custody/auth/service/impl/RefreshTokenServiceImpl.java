package com.custody.auth.service.impl;

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
    private static final int EXPIRATION_DAYS = 7;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TransactionTemplate transactionTemplate;

    @Override
    public RefreshTokenResponse createRefreshToken(String username) {

        if (username == null || username.isBlank()) {
            throw invalidToken();
        }

        // Only callers that have authenticated the user
        // may invoke this operation.
        return transactionTemplate.execute(status -> {

            UserEntity user = userRepository.findByUsername(username).orElseThrow(this::invalidToken);

            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
                throw invalidToken();
            }

            LocalDateTime now = nowUtc();
            LocalDateTime expiresAt =
                    now.plusDays(EXPIRATION_DAYS);

            String rawToken = generateSecureToken();

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

        RotationResult result = transactionTemplate.execute(
                status -> rotateWithinTransaction(tokenHash)
        );

        if (result == null || result.response() == null) {
            throw invalidToken();
        }

        return result.response();
    }

    private RotationResult rotateWithinTransaction(String tokenHash) {
        RefreshTokenEntity current = refreshTokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElse(null);

        if (current == null) {
            return new RotationResult(null);
        }

        LocalDateTime now = nowUtc();

        // A revoked token indicates potential reuse.
        // Revoke the entire token family.
        if (current.getRevokedAt() != null) {
            revokeFamily(current.getTokenFamilyId(), now);
            return new RotationResult(null);
        }

        // Reject expired tokens.
        if (!current.getExpiresAt().isAfter(now)) {
            current.setRevokedAt(now);
            return new RotationResult(null);
        }

        // Check if the user is still active.
        UserEntity user = userRepository
                .findByUsername(current.getUsername())
                .orElse(null);

        if (user == null ||
                !"ACTIVE".equalsIgnoreCase(user.getStatus())) {

            revokeFamily(current.getTokenFamilyId(), now);
            return new RotationResult(null);
        }

        // Generate a new random refresh token.
        String newRawToken = generateSecureToken();

        // Preserve the original session expiration.
        // Rotation does not extend the 7-day lifetime.
        LocalDateTime expiresAt = current.getExpiresAt();

        RefreshTokenEntity replacement =
                new RefreshTokenEntity();

        replacement.setUsername(current.getUsername());
        replacement.setTokenHash(hashToken(newRawToken));
        replacement.setTokenFamilyId(
                current.getTokenFamilyId()
        );
        replacement.setCreatedAt(now);
        replacement.setExpiresAt(expiresAt);

        // Save immediately to obtain the generated ID.
        replacement = refreshTokenRepository
                .saveAndFlush(replacement);

        // Revoke the previous token.
        current.setRevokedAt(now);
        current.setReplacedByTokenId(replacement.getId());

        return new RotationResult(
                new RefreshTokenResponse(
                        newRawToken,
                        current.getUsername(),
                        expiresAt
                )
        );
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {

        String tokenHash = hashToken(refreshToken);

        transactionTemplate.executeWithoutResult(status -> {
            refreshTokenRepository
                    .findByTokenHashForUpdate(tokenHash).ifPresent(current -> revokeFamily(
                            current.getTokenFamilyId(),
                            nowUtc()
                    ));

        });
    }

    private void revokeFamily(String familyId, LocalDateTime revokedAt) {
        List<RefreshTokenEntity> family = refreshTokenRepository.findByTokenFamilyId(familyId);
        for (RefreshTokenEntity token : family) {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(revokedAt);
            }
        }
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

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


    private LocalDateTime nowUtc() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    private InvalidRefreshTokenException invalidToken() {
        return new InvalidRefreshTokenException(
                "Invalid or expired refresh token"
        );
    }

    private record RotationResult(
            RefreshTokenResponse response
    ) {
    }
}
