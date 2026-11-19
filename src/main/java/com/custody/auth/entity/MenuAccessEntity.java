package com.custody.auth.entity;

import jakarta.persistence.*;
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
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "groupName", length = 100, nullable = false)
    private String groupName;

    @Column(name = "menuName", length = 255, nullable = false)
    private String menuName;

}
