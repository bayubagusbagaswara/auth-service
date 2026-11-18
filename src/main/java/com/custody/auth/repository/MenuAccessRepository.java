package com.custody.auth.repository;

import com.custody.auth.entity.MenuAccessEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MenuAccessRepository extends JpaRepository<MenuAccessEntity, Long> {

    List<MenuAccessEntity> findByGroupName(String groupName);

    List<MenuAccessEntity> findByGroupNameOrderByMenuNameAsc(String groupName);

    boolean existsByGroupNameAndMenuName(
            String groupName,
            String menuName
    );

}
