package com.custody.auth.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Configuration for RSA-based JWT authentication.
 * JWT signing algorithm: RS256
 * Private Key:
 * - Used to sign JWT access tokens.
 * Public Key:
 * - Used to validate JWT signatures.
 * - Exposed through the JWKS endpoint.
 */
@Configuration
public class JwtConfig {
    /**
     * Load the RSA private key from a PKCS#8 PEM file.
     *
     * @param properties JWT configuration properties
     * @return RSA private key
     */
    @Bean
    public RSAPrivateKey rsaPrivateKey(
            JwtProperties properties
    ) throws IOException, GeneralSecurityException {

        // 1. Retrieve the configured private key path.
        String privateKeyPath = properties.privateKey();

        // 2. Read the private key PEM file.
        String pem = readPemFile(privateKeyPath);

        // 3. Remove PEM headers, footers and whitespace.
        String encodedKey = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // 4. Decode the Base64 content.
        byte[] decodedKey = Base64.getDecoder()
                .decode(encodedKey);

        // 5. Create the PKCS#8 private key specification.
        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(decodedKey);

        // 6. Generate the RSA private key.
        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    /**
     * Load the RSA public key from an X.509 PEM file.
     *
     * @param properties JWT configuration properties
     * @return RSA public key
     */
    @Bean
    public RSAPublicKey rsaPublicKey(
            JwtProperties properties
    ) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // 1. Retrieve the configured public key path.
        String publicKeyPath = properties.publicKey();

        // 2. Read the public key PEM file.
        String pem = readPemFile(publicKeyPath);

        // 3. Remove PEM headers, footers and whitespace.
        String encodedKey = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // 4. Decode the Base64 content.
        byte[] decodedKey = Base64.getDecoder()
                .decode(encodedKey);

        // 5. Create the X.509 public key specification.
        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(decodedKey);

        // 6. Generate the RSA public key.
        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Configure JWT signing using the RSA private key.
     *
     * @param privateKey RSA private key
     * @param publicKey RSA public key
     * @param properties JWT configuration properties
     * @return JWT encoder
     */
    @Bean
    public JwtEncoder jwtEncoder(
            RSAPrivateKey privateKey,
            RSAPublicKey publicKey,
            JwtProperties properties
    ) {

        // 1. Build the RSA JSON Web Key.
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(properties.keyId())
                .algorithm(JWSAlgorithm.RS256)
                .build();

        // 2. Create the JSON Web Key Set.
        JWKSet jwkSet = new JWKSet(rsaKey);

        // 3. Create an immutable JWK source.
        ImmutableJWKSet<SecurityContext> jwkSource =
                new ImmutableJWKSet<>(jwkSet);

        // 4. Create the Nimbus JWT encoder.
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Configure JWT verification using the RSA public key.
     * Validations:
     * - RS256 signature
     * - Issuer
     * - Expiration
     * - Not-before
     * - Audience
     *
     * @param publicKey RSA public key
     * @param properties JWT configuration properties
     * @return JWT decoder
     */
    @Bean
    public JwtDecoder jwtDecoder(
            RSAPublicKey publicKey,
            JwtProperties properties
    ) {

        // 1. Configure RS256 signature verification.
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        // 2. Configure standard JWT validation.
        // Validates issuer, expiration and not-before claims.
        OAuth2TokenValidator<@NonNull Jwt> defaultValidator =
                JwtValidators.createDefaultWithIssuer(
                        properties.issuer()
                );

        // 3. Validate the required auth-service audience.
        OAuth2TokenValidator<@NonNull Jwt> audienceValidator = jwt -> {

            // Check whether this token is intended for auth-service.
            boolean valid = jwt.getAudience() != null
                    && jwt.getAudience().contains("auth-service");

            if (valid) {
                return OAuth2TokenValidatorResult.success();
            }

            // Reject tokens without the required audience.
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(
                            "invalid_token",
                            "Invalid JWT audience",
                            null
                    )
            );
        };

        // 4. Combine standard and audience validators.
        OAuth2TokenValidator<@NonNull Jwt> validator =
                new DelegatingOAuth2TokenValidator<>(
                        defaultValidator,
                        audienceValidator
                );

        // 5. Register JWT validators.
        decoder.setJwtValidator(validator);

        return decoder;
    }

    /**
     * Read a PEM file from the configured file system path.
     *
     * @param filePath path to PEM file
     * @return PEM file content
     * @throws IOException if the PEM file cannot be read
     */
    private String readPemFile(
            String filePath
    ) throws IOException {

        // 1. Resolve the configured key file path.
        Path path = Path.of(filePath);

        // 2. Read the PEM file using UTF-8.
        return Files.readString(
                path,
                StandardCharsets.UTF_8
        );
    }

}
