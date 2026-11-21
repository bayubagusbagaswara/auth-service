package com.custody.auth.service;

import com.custody.auth.dto.response.LdapTestResponse;

public interface LdapTestService {

    /**
     * Test TCP connectivity to LDAP.
     */
    LdapTestResponse testTcpConnection();

    /**
     * Test LDAPS TLS handshake and certificate validation.
     */
    LdapTestResponse testTlsConnection();

    /**
     * Authenticate a user using LDAP simple bind over TLS.
     *
     * Username must use a format accepted by the directory,
     * such as a UPN or distinguished name.
     */
    LdapTestResponse testAuthentication(
            String username,
            String password
    );

}
