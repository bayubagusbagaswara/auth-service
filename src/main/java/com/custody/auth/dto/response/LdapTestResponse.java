package com.custody.auth.dto.response;

public record LdapTestResponse(
        String test,

        boolean success,

        String code,

        String message
) {
}
