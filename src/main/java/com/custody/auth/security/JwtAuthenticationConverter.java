package com.custody.auth.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter delegate;

    public JwtAuthenticationConverter() {

        var authoritiesConverter =
                new org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter();

        // Read permissions from the custom "menus" claim.
        authoritiesConverter.setAuthoritiesClaimName("menus");

        // Keep menu names unchanged.
        authoritiesConverter.setAuthorityPrefix("");

        delegate =
                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter();

        delegate.setJwtGrantedAuthoritiesConverter(
                authoritiesConverter
        );
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        return delegate.convert(jwt);
    }

}
