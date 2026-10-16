package com.talentmatch.platform.tenant.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TenantContext {
	private final Long springUserId;
    private final Integer legacySqliteUserId;
    private final String tenantId;
    private final String systemType;
    private final String role;
    private final boolean profileCompleted;
    private final String candidateProfileId; 

}
