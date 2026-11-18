package com.custody.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "csa_menu_access")
@Getter
@Setter
@NoArgsConstructor
public class MenuAccessEntity {

    @Id
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "groupName", length = 100, nullable = false)
    private String groupName;

    @Column(name = "menuName", length = 150, nullable = false)
    private String menuName;

}
