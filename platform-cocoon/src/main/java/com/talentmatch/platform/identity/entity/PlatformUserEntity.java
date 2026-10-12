package com.talentmatch.platform.identity.entity;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name="platform_users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PlatformUserEntity {
	
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 80)
    private String username;

    @Column(nullable = false, unique = true, length = 120)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 256)
    private String passwordHash;

    @Column(nullable = false, length = 20)
    private String role;

    @Column(name = "company_name", length = 100)
    private String companyName;

    @Column(name = "candidate_profile_id", length = 100)
    private String candidateProfileId;

    @Column(name = "profile_completed")
    private Boolean profileCompleted = false;

    @Column(name = "institution_name", length = 150)
    private String institutionName;

    @Column(name = "institution_domain", length = 100)
    private String institutionDomain;

    @Column(length = 100)
    private String department;

    // === SPRING EXTENSIONS ===
    @Column(name = "legacy_sqlite_user_id")
    private Integer legacySqliteUserId;

    @Column(name = "tenant_id", nullable = false, length = 100)
    private String tenantId;

    @Column(name = "system_type", nullable = false, length = 20)
    private String systemType;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

}
