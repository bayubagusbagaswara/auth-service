package com.custody.auth.controller;

import com.custody.auth.dto.request.LdapBindRequest;
import com.custody.auth.dto.response.LdapTestResponse;
import com.custody.auth.service.LdapTestService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Temporary LDAP diagnostic controller.
 * Available only when:
 * - Spring profile: dev
 * - app.ldap.diagnostics.enabled: true
 * Must not be exposed in production.
 */
@RestController
@RequestMapping("/api/v1/dev/ldap")
@RequiredArgsConstructor
@Profile("dev")
@ConditionalOnProperty(
        prefix = "app.ldap.diagnostics",
        name = "enabled",
        havingValue = "true"
)
@PreAuthorize("authentication.name == 'admin'")
public class LdapController {

    private final LdapTestService ldapTestService;

    /**
     * Test basic TCP connectivity.
     */
    @GetMapping("/connectivity")
    public ResponseEntity<@NonNull LdapTestResponse> testConnectivity(
            HttpServletRequest request
    ) {

        // Only allow local diagnostic requests.
        if (isLocalRequest(request)) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .build();
        }

        return ResponseEntity.ok(
                ldapTestService.testTcpConnection()
        );
    }

    /**
     * Test LDAPS handshake and certificate verification.
     */
    @GetMapping("/tls")
    public ResponseEntity<@NonNull LdapTestResponse> testTls(
            HttpServletRequest request
    ) {

        if (isLocalRequest(request)) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .build();
        }

        return ResponseEntity.ok(
                ldapTestService.testTlsConnection()
        );
    }

    /**
     * Test LDAP bind authentication.
     * Password is forwarded to LDAP over TLS.
     * It is not saved or returned in the response.
     */
    @PostMapping("/authenticate")
    public ResponseEntity<@NonNull LdapTestResponse> authenticate(
            @Valid @RequestBody LdapBindRequest body,
            HttpServletRequest request
    ) {

        if (isLocalRequest(request)) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .build();
        }

        return ResponseEntity.ok(
                ldapTestService.testAuthentication(
                        body.username(),
                        body.password()
                )
        );
    }

    /**
     * Check whether the request originates locally.
     * This is an additional development-only restriction,
     * not a replacement for strong authentication.
     */
    private boolean isLocalRequest(
            HttpServletRequest request
    ) {

        String remoteAddress = request.getRemoteAddr();

        return !"127.0.0.1".equals(remoteAddress)
                && !"::1".equals(remoteAddress)
                && !"0:0:0:0:0:0:0:1".equals(remoteAddress);
    }

}
