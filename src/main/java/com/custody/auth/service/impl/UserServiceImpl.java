package com.custody.auth.service.impl;

import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.ResourceNotFoundException;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.MenuAccessService;
import com.custody.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final MenuAccessService menuAccessService;

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByUsername(String username) {

        // Find user in csa_users
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found: " + username
                        )
                );

        // Retrieve accessible menus based on group level.
        List<String> menus = menuAccessService.getMenusByGroupName(user.getGroupLevel());

        // Convert user information to response DTO.
        return new UserResponse(
                user.getUsername(),
                user.getSurename(), // Mapped to fullName.
                user.getBranchName(),
                user.getStatus(),
                user.getGroupLevel(),
                user.getLastLogin(),
                menus
        );
    }

}
