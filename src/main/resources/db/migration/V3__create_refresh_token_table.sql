
-- =========================================================
-- V3: Create Refresh Token Table
-- =========================================================

CREATE TABLE csa_refresh_token (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_family_id CHAR(36) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    replaced_by_token_id BIGINT NULL,

    CONSTRAINT pk_csa_refresh_token
        PRIMARY KEY (id),

    CONSTRAINT uk_csa_refresh_token_hash
        UNIQUE (token_hash),

    CONSTRAINT fk_csa_refresh_token_username
        FOREIGN KEY (username)
        REFERENCES csa_users(username)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Index for refresh token family operations.
CREATE INDEX idx_csa_refresh_token_family
    ON csa_refresh_token(token_family_id);

-- Index for retrieving sessions by username.
CREATE INDEX idx_csa_refresh_token_username
    ON csa_refresh_token(username);
