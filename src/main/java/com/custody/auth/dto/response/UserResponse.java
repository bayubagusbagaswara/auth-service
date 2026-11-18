package com.custody.auth.dto.response;

import java.time.LocalDateTime;
import java.util.List;

/**
 * {
 *   "username": "testuser",
 *   "fullName": "Test User",
 *   "branchName": "JKT-HO",
 *   "status": "ACTIVE",
 *   "groupLevel": "Support User",
 *   "lastLogin": null,
 *   "menus": [
 *     "compliance_EditBreachDays",
 *     "compliance_InquiryBreachDays",
 *     "compliance_InquiryLiquidation",
 *     "compliance_LiquidationMaintenance"
 *   ]
 * }
 */

public record UserResponse(
        String username,
        String fullName,
        String branchName,
        String status,
        String groupLevel,
        LocalDateTime lastLogin,
        List<String> menus
) {

}
