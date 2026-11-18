package com.custody.auth.service;

import com.custody.auth.dto.request.LoginRequest;
import com.custody.auth.dto.response.AuthResponse;

public interface LoginService {

    AuthResponse login(LoginRequest request);

}
