package com.custody.auth.service;

import com.custody.auth.entity.UserEntity;

import java.util.List;

public interface JwtService {

    String generateAccessToken(
            UserEntity user,
            List<String> menus
    );

}
