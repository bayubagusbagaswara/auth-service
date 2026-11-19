
-- Seed sample users for development.
-- Existing table: CSAUSERS

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
    UTC_TIMESTAMP(),
    NULL,
    'ADMIN',
    'Sample administrator',
    'ACTIVE',
    'Y',
    0
),
(
    'developer',
    'Development User',
    'JKT-HO',
    'ACTIVE',
    UTC_TIMESTAMP(),
    NULL,
    'SUPPORT',
    'Sample support user',
    'ACTIVE',
    'Y',
    0
),
(
    'operator',
    'Custody Operator',
    'JKT-HO',
    'ACTIVE',
    UTC_TIMESTAMP(),
    NULL,
    'OPERATOR',
    'Sample operator',
    'ACTIVE',
    'Y',
    0
),
(
    'inactive',
    'Inactive User',
    'JKT-HO',
    'INACTIVE',
    UTC_TIMESTAMP(),
    NULL,
    'OPERATOR',
    'Sample inactive user',
    'INACTIVE',
    'Y',
    0
);
