package com.custody.auth.config;

import com.custody.auth.service.LdapTestService;
import com.custody.auth.service.impl.LdapTestServiceImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Configuration for temporary LDAP diagnostic testing.
 * Available only when:
 * 1. Spring profile is dev.
 * 2. LDAP diagnostics are explicitly enabled.
 */
@Configuration
@Profile("dev")
@ConditionalOnProperty(
        prefix = "app.ldap.diagnostics",
        name = "enabled",
        havingValue = "true"
)
public class LdapTestConfig {

    @Bean
    public LdapTestService ldapTestService(
            @Value("${app.ldap.host}") String host,
            @Value("${app.ldap.port:636}") int port,
            @Value("${app.ldap.connect-timeout-ms:5000}")
            int connectTimeoutMs,
            @Value("${app.ldap.read-timeout-ms:5000}")
            int readTimeoutMs
    ) {

        // Create LDAP diagnostic service.
        return new LdapTestServiceImpl(
                host,
                port,
                connectTimeoutMs,
                readTimeoutMs
        );
    }
}
