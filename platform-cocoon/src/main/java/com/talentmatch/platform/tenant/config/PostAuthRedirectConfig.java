package com.talentmatch.platform.tenant.config;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

/**
 * Centralized post-auth redirect mapping.
 * Values can be Flask routes (Step 1), Spring routes (Step 3), or external URLs.
 * Changed via application.yml without recompilation.
 */
@Data
@Component
@ConfigurationProperties(prefix = "platform.redirects")  // ← FIXED: was "platform.redirect"
public class PostAuthRedirectConfig {

	
    /**
     * Key: systemType (CANDIDATE, CORP, UNIVERSITY, ADMIN)
     * Value: redirect URL pattern. Supports placeholders: {tenantId}, {candidateProfileId}, {userId}
     */
    private Map<String, String> defaultRedirects = Map.of(
        "ADMIN", "/admin/matches",
        "CORP", "/api/jd/jd_dashboard",           // ← Verify against your Flask @app.route()
        "UNIVERSITY", "/campus/dashboard",     // ← Verify against your Flask @app.route()
        "CANDIDATE", "/upload?default_type=candidate"                 // ← FIXED: was "/dashbard/candidate/upload"
    );

    /**
     * Conditional redirects based on user state.
     * Key: systemType:condition (e.g., "CANDIDATE:profileCompleted")
     */
    private Map<String, String> conditionalRedirects = Map.of(
        "CANDIDATE:profileCompleted", "/fit_analysis/{candidateProfileId}"
    );
}