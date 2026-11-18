package com.custody.auth.service;

import com.custody.auth.dto.response.AuthResponse;
import com.custody.auth.dto.response.UserResponse;

public interface AuthService {

    AuthResponse refreshToken(String refreshToken);

    void logout(String refreshToken);

    UserResponse getCurrentUser(String username);

}
