package com.custody.auth.service;

import com.custody.auth.dto.response.UserResponse;

public interface UserService {

    UserResponse getUserByUsername(String username);

}
