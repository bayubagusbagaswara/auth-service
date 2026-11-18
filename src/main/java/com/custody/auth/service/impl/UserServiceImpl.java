package com.custody.auth.service.impl;

import com.custody.auth.dto.response.UserResponse;
import com.custody.auth.entity.MenuAccessEntity;
import com.custody.auth.entity.UserEntity;
import com.custody.auth.exception.ResourceNotFoundException;
import com.custody.auth.repository.MenuAccessRepository;
import com.custody.auth.repository.UserRepository;
import com.custody.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final MenuAccessRepository menuAccessRepository;

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByUsername(String username) {

        // Find user by username.
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found: " + username
                        )
                );

        // Retrieve the user's access group.
        String groupName = user.getGroupLevel();

        // Retrieve menu permissions based on the user's group.
        List<String> menus = groupName == null || groupName.isBlank()
                ? List.of()
                : menuAccessRepository
                .findByGroupNameOrderByMenuNameAsc(groupName)
                .stream()
                .map(MenuAccessEntity::getMenuName)
                .distinct()
                .toList();

        // Map user entity and permissions to response DTO.
        return new UserResponse(
                user.getUsername(),
                user.getSurename(),
                user.getBranchName(),
                user.getStatus(),
                user.getGroupLevel(),
                user.getLastLogin(),
                menus
        );
    }

}
