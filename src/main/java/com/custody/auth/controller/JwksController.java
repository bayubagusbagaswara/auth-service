package com.custody.auth.controller;

import com.custody.auth.config.JwtProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final RSAPublicKey rsaPublicKey;
    private final JwtProperties jwtProperties;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {

        // Build JWK using the RSA public key only.
        RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                .keyID(jwtProperties.keyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        // Create a JSON Web Key Set.
        JWKSet jwkSet = new JWKSet(rsaKey);

        // Return only public key information.
        return ResponseEntity.ok(jwkSet.toJSONObject());
    }
}
