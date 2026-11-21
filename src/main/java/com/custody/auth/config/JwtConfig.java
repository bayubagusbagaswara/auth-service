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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
    private static final String RSA_ALGORITHM = "RSA";

    private static final String PRIVATE_KEY_TYPE = "PRIVATE KEY";

    private static final String PUBLIC_KEY_TYPE = "PUBLIC KEY";

    private static final String REQUIRED_AUDIENCE = "auth-service";

    /**
     * Load an RSA private key from a PKCS#8 PEM file.
     *
     * @param properties JWT configuration properties
     * @return RSA private key
     * @throws IOException if the key file cannot be read
     * @throws GeneralSecurityException if the key is invalid
     */
    @Bean
    public RSAPrivateKey rsaPrivateKey(
            JwtProperties properties
    ) throws IOException, GeneralSecurityException {

        // 1. Retrieve the configured private key path.
        String privateKeyPath = properties.privateKey();

        // 2. Read the private key PEM file.
        String pem = readPemFile(privateKeyPath);

        // 3. Decode the PKCS#8 PEM content.
        byte[] decodedKey = decodePemKey(
                pem,
                PRIVATE_KEY_TYPE
        );

        // 4. Create the PKCS#8 private key specification.
        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(decodedKey);

        // 5. Initialize the RSA key factory.
        KeyFactory keyFactory =
                KeyFactory.getInstance(RSA_ALGORITHM);

        // 6. Generate and return the RSA private key.
        return (RSAPrivateKey) keyFactory.generatePrivate(
                keySpec
        );
    }

    /**
     * Load an RSA public key from an X.509 PEM file.
     *
     * @param properties JWT configuration properties
     * @return RSA public key
     * @throws IOException if the key file cannot be read
     * @throws GeneralSecurityException if the key is invalid
     */
    @Bean
    public RSAPublicKey rsaPublicKey(
            JwtProperties properties
    ) throws IOException, GeneralSecurityException {

        // 1. Retrieve the configured public key path.
        String publicKeyPath = properties.publicKey();

        // 2. Read the public key PEM file.
        String pem = readPemFile(publicKeyPath);

        // 3. Decode the X.509 PEM content.
        byte[] decodedKey = decodePemKey(
                pem,
                PUBLIC_KEY_TYPE
        );

        // 4. Create the X.509 public key specification.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);

        // 5. Initialize the RSA key factory.
        KeyFactory keyFactory =
                KeyFactory.getInstance(RSA_ALGORITHM);

        // 6. Generate and return the RSA public key.
        return (RSAPublicKey) keyFactory.generatePublic(
                keySpec
        );
    }

    /**
     * Configure JWT signing using RS256.
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
     * - Required audience
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
        OAuth2TokenValidator<@NonNull Jwt> defaultValidator =
                JwtValidators.createDefaultWithIssuer(
                        properties.issuer()
                );

        // 3. Validate the required Auth Service audience.
        OAuth2TokenValidator<@NonNull Jwt> audienceValidator =
                jwt -> {

                    // Verify that the token is intended
                    // for Auth Service.
                    boolean valid = jwt.getAudience() != null
                            && jwt.getAudience()
                            .contains(REQUIRED_AUDIENCE);

                    if (valid) {
                        return OAuth2TokenValidatorResult.success();
                    }

                    // Reject tokens with an invalid audience.
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

        // 5. Register the JWT validators.
        decoder.setJwtValidator(validator);

        return decoder;
    }

    /**
     * Decode a PEM-formatted RSA key.
     * Supports:
     * - PKCS#8 private keys
     * - X.509 public keys
     * PEM boundaries are constructed dynamically
     * instead of using complete literal markers.
     *
     * @param pem PEM-formatted key content
     * @param keyType expected PEM key type
     * @return decoded DER key bytes
     */
    private byte[] decodePemKey(
            String pem,
            String keyType
    ) {

        // 1. Construct the PEM boundary markers.
        String delimiter = "-".repeat(5);

        String header =
                delimiter + "BEGIN " + keyType + delimiter;

        String footer =
                delimiter + "END " + keyType + delimiter;

        // 2. Remove leading and trailing whitespace.
        String normalizedPem = pem.strip();

        // 3. Validate the expected PEM boundaries.
        if (!normalizedPem.startsWith(header)
                || !normalizedPem.endsWith(footer)) {

            throw new IllegalArgumentException(
                    "Invalid PEM format for " + keyType
            );
        }

        // 4. Extract the Base64 content.
        String encodedKey = normalizedPem.substring(
                header.length(),
                normalizedPem.length() - footer.length()
        );

        // 5. Remove all whitespace from Base64 content.
        encodedKey = encodedKey.replaceAll("\\s+", "");

        // 6. Decode Base64 into DER-encoded key bytes.
        return Base64.getDecoder().decode(encodedKey);
    }

    /**
     * Read a PEM file from the configured filesystem path.
     *
     * @param filePath path to the PEM file
     * @return PEM file content
     * @throws IOException if the file cannot be read
     */
    private String readPemFile(
            String filePath
    ) throws IOException {

        // 1. Resolve the configured file path.
        Path path = Path.of(filePath);

        // 2. Read the PEM file using UTF-8.
        return Files.readString(
                path,
                StandardCharsets.UTF_8
        );
    }

}
