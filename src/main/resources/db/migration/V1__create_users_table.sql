
-- =========================================================
-- V1: Create Users Table
-- =========================================================

CREATE TABLE csa_users (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    surename VARCHAR(255) NULL,
    password VARCHAR(255) NULL,
    passwordExpired VARCHAR(50) NULL,
    branchName VARCHAR(100) NULL,
    status VARCHAR(30) NULL,
    dateCreation DATETIME(6) NULL,
    LastLogin DATETIME(6) NULL,
    groupLevel VARCHAR(100) NULL,
    notes TEXT NULL,
    appStatus VARCHAR(30) NULL,
    firstLogin VARCHAR(10) NULL,
    invalidLog INT NULL,

    CONSTRAINT pk_csa_users
        PRIMARY KEY (id),

    CONSTRAINT uk_csa_users_username
        UNIQUE (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
