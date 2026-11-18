package com.custody.auth.service.impl;

import com.custody.auth.entity.MenuAccessEntity;
import com.custody.auth.repository.MenuAccessRepository;
import com.custody.auth.service.MenuAccessService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MenuAccessServiceImpl implements MenuAccessService {

    private final MenuAccessRepository menuAccessRepository;

    @Override
    @Transactional(readOnly = true)
    public List<String> getMenusByGroupName(String groupName) {
        // Return an empty list if group name is missing.
        if (groupName == null || groupName.isBlank()) {
            return List.of();
        }

        // Retrieve menus from the database.
        return menuAccessRepository
                .findByGroupNameOrderByMenuNameAsc(groupName)
                .stream()
                .map(MenuAccessEntity::getMenuName)
                .distinct()
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean hasMenuAccess(String groupName, String menuName) {
        // Reject invalid parameters.
        if (groupName == null || groupName.isBlank()
                || menuName == null || menuName.isBlank()) {
            return false;
        }

        // Check menu permission in the database.
        return menuAccessRepository
                .existsByGroupNameAndMenuName(
                        groupName,
                        menuName
                );
    }

}
