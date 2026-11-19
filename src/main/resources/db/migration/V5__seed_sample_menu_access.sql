
-- =========================================================
-- V5: Seed Sample Menu Access
-- =========================================================

INSERT INTO csa_menu_access (
    groupName,
    menuName
)
VALUES

-- ADMIN permissions
('ADMIN', 'compliance_InquiryLiquidation'),
('ADMIN', 'compliance_EditBreachDays'),
('ADMIN', 'compliance_InquiryBreachDays'),
('ADMIN', 'compliance_LiquidationMaintenance'),
('ADMIN', 'billing_InquiryInvoice'),
('ADMIN', 'billing_CreateInvoice'),
('ADMIN', 'core_InquiryTransaction'),
('ADMIN', 'core_CreateTransaction'),
('ADMIN', 'hiport_InquiryPortfolio'),

-- SUPPORT permissions
('SUPPORT', 'compliance_InquiryLiquidation'),
('SUPPORT', 'compliance_InquiryBreachDays'),
('SUPPORT', 'billing_InquiryInvoice'),
('SUPPORT', 'core_InquiryTransaction'),
('SUPPORT', 'hiport_InquiryPortfolio'),

-- OPERATOR permissions
('OPERATOR', 'compliance_InquiryLiquidation'),
('OPERATOR', 'billing_InquiryInvoice'),
('OPERATOR', 'core_InquiryTransaction');
