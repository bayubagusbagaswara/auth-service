package com.custody.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Entity representing the CSAUSERS table.
 * Stores user information, account status,
 * branch information, and access group.
 */
@Entity
@Table(name = "csa_users")
@Getter
@Setter
@NoArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", length = 64, nullable = false)
    private String username;

    @Column(name = "surename", length = 150)
    private String surename;

    @Column(name = "branchName", length = 100)
    private String branchName;

    @Column(name = "status", length = 30)
    private String status;

    @Column(name = "dateCreation")
    private LocalDateTime dateCreation;

    @Column(name = "LastLogin")
    private LocalDateTime lastLogin;

    @Column(name = "groupLevel", length = 100)
    private String groupLevel;

    @Column(name = "notes", length = 255)
    private String notes;

    @Column(name = "appStatus", length = 30)
    private String appStatus;

    @Column(name = "firstLogin", length = 30)
    private String firstLogin;

    @Column(name = "invalidLog")
    private Integer invalidLog;

}
