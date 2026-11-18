package com.custody.auth.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    /**
     * Load the RSA private key from a PEM file.
     */
    @Bean
    public RSAPrivateKey rsaPrivateKey(
            JwtProperties properties
    ) throws Exception {

        String pem = Files.readString(
                Path.of(properties.privateKey()),
                StandardCharsets.UTF_8
        );

        String privateKey = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder()
                .decode(privateKey);

        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(decoded);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory
                .generatePrivate(keySpec);
    }

    /**
     * Load the RSA public key from a PEM file.
     */
    @Bean
    public RSAPublicKey rsaPublicKey(
            JwtProperties properties
    ) throws Exception {

        String pem = Files.readString(
                Path.of(properties.publicKey()),
                StandardCharsets.UTF_8
        );

        String publicKey = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder()
                .decode(publicKey);

        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory
                .generatePublic(keySpec);
    }

    /**
     * Create a JWT encoder using the RSA key pair.
     *
     * The private key signs the JWT.
     */
    @Bean
    public JwtEncoder jwtEncoder(
            RSAPublicKey publicKey,
            RSAPrivateKey privateKey,
            JwtProperties properties
    ) {

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(properties.keyId())
                .build();

        JWKSource<SecurityContext> jwkSource =
                new ImmutableJWKSet<>(
                        new com.nimbusds.jose.jwk.JWKSet(rsaKey)
                );

        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Create a JWT decoder using the RSA public key.
     *
     * Validates signature, timestamps, and issuer.
     */
    @Bean
    public JwtDecoder jwtDecoder(
            RSAPublicKey publicKey,
            JwtProperties properties
    ) {

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(publicKey)
                .build();

        decoder.setJwtValidator(
                JwtValidators.createDefaultWithIssuer(
                        properties.issuer()
                )
        );

        return decoder;
    }

}
