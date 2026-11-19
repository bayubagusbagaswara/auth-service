
-- =========================================================
-- V2: Create Menu Access Table
-- =========================================================

CREATE TABLE csa_menu_access (
    id BIGINT NOT NULL AUTO_INCREMENT,
    groupName VARCHAR(100) NOT NULL,
    menuName VARCHAR(255) NOT NULL,

    CONSTRAINT pk_csa_menu_access
        PRIMARY KEY (id),

    CONSTRAINT uk_csa_menu_access_group_menu
        UNIQUE (groupName, menuName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
