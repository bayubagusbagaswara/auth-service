
-- =========================================================
-- V4: Seed Sample Users
-- =========================================================

INSERT INTO csa_users (
    username,
    surename,
    branchName,
    status,
    dateCreation,
    LastLogin,
    groupLevel,
    notes,
    appStatus,
    firstLogin,
    invalidLog
)
VALUES
(
    'admin',
    'System Administrator',
    'JKT-HO',
    'ACTIVE',
    UTC_TIMESTAMP(6),
    NULL,
    'ADMIN',
    'Sample administrator account',
    'ACTIVE',
    'Y',
    0
),
(
    'developer',
    'Development User',
    'JKT-HO',
    'ACTIVE',
    UTC_TIMESTAMP(6),
    NULL,
    'SUPPORT',
    'Sample developer account',
    'ACTIVE',
    'Y',
    0
),
(
    'operator',
    'Custody Operator',
    'JKT-HO',
    'ACTIVE',
    UTC_TIMESTAMP(6),
    NULL,
    'OPERATOR',
    'Sample operator account',
    'ACTIVE',
    'Y',
    0
),
(
    'inactive',
    'Inactive User',
    'JKT-HO',
    'INACTIVE',
    UTC_TIMESTAMP(6),
    NULL,
    'OPERATOR',
    'Sample inactive account',
    'INACTIVE',
    'Y',
    0
);
