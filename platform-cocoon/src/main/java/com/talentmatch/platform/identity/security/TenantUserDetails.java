package com.talentmatch.platform.identity.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.talentmatch.platform.identity.entity.PlatformUserEntity;

import lombok.Getter;

@Getter
public class TenantUserDetails implements UserDetails{
	
	private final Long springUserId;
    private final Integer legacySqliteUserId;
    private final String username;
    private final String passwordHash;
    private final String tenantId;
    private final String systemType;
    private final String role;
    private final boolean profileCompleted;
    private final Collection<? extends GrantedAuthority> authorities;
    
    public TenantUserDetails(PlatformUserEntity user) {
        this.springUserId = user.getId();
        this.legacySqliteUserId = user.getLegacySqliteUserId();
        this.username = user.getUsername();
        this.passwordHash = user.getPasswordHash();
        this.tenantId = user.getTenantId();
        this.systemType = user.getSystemType();
        this.role = user.getRole();
        this.profileCompleted = Boolean.TRUE.equals(user.getProfileCompleted());
        this.authorities = List.of(
            new SimpleGrantedAuthority("ROLE_" + user.getRole().toUpperCase()),
            new SimpleGrantedAuthority("SYSTEM_" + user.getSystemType())
        );
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }

    @Override
    public String getPassword() { return passwordHash; }

    @Override
    public String getUsername() { return username; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

}
