package com.custody.auth.service.impl;

import com.custody.auth.dto.response.LdapTestResponse;
import com.custody.auth.service.LdapTestService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Hashtable;

public class LdapTestServiceImpl implements LdapTestService {

    private static final Logger log =
            LoggerFactory.getLogger(LdapTestServiceImpl.class);

    private final String host;
    private final int port;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public LdapTestServiceImpl(
            String host,
            int port,
            int connectTimeoutMs,
            int readTimeoutMs
    ) {
        this.host = host;
        this.port = port;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * Test whether the LDAP server is reachable via TCP.
     *
     * This test does not validate TLS or user credentials.
     */
    @Override
    public LdapTestResponse testTcpConnection() {

        try (Socket socket = new Socket()) {

            // 1. Connect to LDAP host and port.
            socket.connect(
                    new InetSocketAddress(host, port),
                    connectTimeoutMs
            );

            // 2. Return successful connectivity result.
            return success(
                    "TCP_CONNECTION",
                    "LDAP TCP connection successful"
            );

        } catch (Exception exception) {

            // Log only the exception type, never credentials.
            log.warn(
                    "LDAP TCP test failed: {}",
                    exception.getClass().getSimpleName()
            );

            return failure(
                    "TCP_CONNECTION",
                    "CONNECTION_FAILED",
                    "Unable to connect to LDAP server"
            );
        }
    }

    /**
     * Test LDAPS TLS connection and certificate validation.
     *
     * The test verifies:
     * 1. Network connectivity
     * 2. TLS handshake
     * 3. Server certificate trust
     * 4. Server hostname
     */
    @Override
    public LdapTestResponse testTlsConnection() {

        // LDAPS normally uses port 636.
        // Plain LDAP/StartTLS on 389 is not supported here.
        if (port != 636) {
            return failure(
                    "LDAPS_TLS",
                    "UNSUPPORTED_PORT",
                    "This diagnostic requires LDAPS port 636"
            );
        }

        SSLSocketFactory factory =
                (SSLSocketFactory) SSLSocketFactory
                        .getDefault();

        try (SSLSocket socket =
                     (SSLSocket) factory.createSocket()) {

            // 1. Establish TCP connection.
            socket.connect(
                    new InetSocketAddress(host, port),
                    connectTimeoutMs
            );

            // 2. Configure read timeout.
            socket.setSoTimeout(readTimeoutMs);

            // 3. Enable server hostname verification.
            SSLParameters parameters =
                    socket.getSSLParameters();

            parameters.setEndpointIdentificationAlgorithm(
                    "HTTPS"
            );

            socket.setSSLParameters(parameters);

            // 4. Perform TLS handshake.
            socket.startHandshake();

            // 5. Return success when TLS verification passes.
            return success(
                    "LDAPS_TLS",
                    "LDAPS TLS verification successful"
            );

        } catch (Exception exception) {

            log.warn(
                    "LDAPS TLS test failed: {}",
                    exception.getClass().getSimpleName()
            );

            return failure(
                    "LDAPS_TLS",
                    "TLS_VERIFICATION_FAILED",
                    "LDAPS connection or TLS verification failed"
            );
        }
    }

    /**
     * Authenticate a directory user using LDAP simple bind
     * over an encrypted LDAPS connection.
     *
     * The provided username must be a bind identity
     * accepted by the LDAP server.
     *
     * No LDAP password is stored in the database.
     */
    @Override
    public LdapTestResponse testAuthentication(
            String username,
            String password
    ) {

        // 1. Reject unencrypted LDAP authentication.
        if (port != 636) {
            return failure(
                    "LDAP_AUTHENTICATION",
                    "INSECURE_CONFIGURATION",
                    "LDAP authentication requires LDAPS"
            );
        }

        // 2. Validate input.
        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            return failure(
                    "LDAP_AUTHENTICATION",
                    "INVALID_REQUEST",
                    "Username and password are required"
            );
        }

        // 3. Prepare JNDI environment.
        Hashtable<String, Object> environment =
                new Hashtable<>();

        environment.put(
                Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory"
        );

        // Use the hostname so that TLS certificate
        // verification can validate the server identity.
        environment.put(
                Context.PROVIDER_URL,
                "ldaps://" + host + ":" + port
        );

        // Simple bind with username and password.
        environment.put(
                Context.SECURITY_AUTHENTICATION,
                "simple"
        );

        environment.put(
                Context.SECURITY_PRINCIPAL,
                username
        );

        environment.put(
                Context.SECURITY_CREDENTIALS,
                password
        );

        // Configure connection and read timeouts.
        environment.put(
                "com.sun.jndi.ldap.connect.timeout",
                String.valueOf(connectTimeoutMs)
        );

        environment.put(
                "com.sun.jndi.ldap.read.timeout",
                String.valueOf(readTimeoutMs)
        );

        // Explicitly avoid LDAP connection pooling.
        environment.put(
                "com.sun.jndi.ldap.connect.pool",
                "false"
        );

        InitialLdapContext context = null;

        try {

            // 4. Establish LDAPS connection and bind.
            context = new InitialLdapContext(
                    environment,
                    null
            );

            // 5. Bind succeeded if no exception occurred.
            return success(
                    "LDAP_AUTHENTICATION",
                    "LDAP authentication successful"
            );

        } catch (AuthenticationException exception) {

            // Invalid credentials or account restrictions.
            // Do not expose detailed directory error codes.
            log.warn("LDAP authentication rejected");

            return failure(
                    "LDAP_AUTHENTICATION",
                    "AUTHENTICATION_FAILED",
                    "LDAP authentication was rejected"
            );

        } catch (NamingException exception) {

            // Connection, TLS, DNS, or directory errors.
            log.warn(
                    "LDAP bind test failed: {}",
                    exception.getClass().getSimpleName()
            );

            return failure(
                    "LDAP_AUTHENTICATION",
                    "LDAP_UNAVAILABLE",
                    "LDAP authentication could not be completed"
            );

        } finally {

            // 6. Close the directory connection.
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException exception) {
                    log.debug("LDAP context close failed");
                }
            }

            // 7. Remove credentials from the JNDI map.
            environment.remove(
                    Context.SECURITY_CREDENTIALS
            );
        }
    }

    /**
     * Build a successful diagnostic response.
     */
    private LdapTestResponse success(
            String test,
            String message
    ) {

        return new LdapTestResponse(
                test,
                true,
                "CONNECTION_SUCCESS",
                message
        );
    }

    /**
     * Build a failed diagnostic response.
     */
    private LdapTestResponse failure(
            String test,
            String code,
            String message
    ) {

        return new LdapTestResponse(
                test,
                false,
                code,
                message
        );
    }

}
