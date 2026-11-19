
-- Seed sample menu permissions.
-- Existing table: CSAMENUACCESS

INSERT INTO csa_menu_access (
    id,
    groupName,
    menuName
)
VALUES
-- ADMIN permissions
(1001, 'ADMIN', 'compliance_InquiryLiquidation'),
(1002, 'ADMIN', 'compliance_EditBreachDays'),
(1003, 'ADMIN', 'compliance_InquiryBreachDays'),
(1004, 'ADMIN', 'billing_InquiryInvoice'),
(1005, 'ADMIN', 'billing_CreateInvoice'),
(1006, 'ADMIN', 'core_InquiryTransaction'),
(1007, 'ADMIN', 'core_CreateTransaction'),
(1008, 'ADMIN', 'hiport_InquiryPortfolio'),

-- SUPPORT permissions
(2001, 'SUPPORT', 'compliance_InquiryLiquidation'),
(2002, 'SUPPORT', 'compliance_InquiryBreachDays'),
(2003, 'SUPPORT', 'billing_InquiryInvoice'),
(2004, 'SUPPORT', 'core_InquiryTransaction'),
(2005, 'SUPPORT', 'hiport_InquiryPortfolio'),

-- OPERATOR permissions
(3001, 'OPERATOR', 'compliance_InquiryLiquidation'),
(3002, 'OPERATOR', 'billing_InquiryInvoice'),
(3003, 'OPERATOR', 'core_InquiryTransaction');
