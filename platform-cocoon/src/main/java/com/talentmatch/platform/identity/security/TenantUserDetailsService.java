package com.talentmatch.platform.identity.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.talentmatch.platform.identity.entity.PlatformUserEntity;
import com.talentmatch.platform.identity.repository.PlatformUserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class TenantUserDetailsService implements UserDetailsService {
	
	private final PlatformUserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		CurrentAuthUsernameHolder.setUsername(username);
		PlatformUserEntity user = userRepository.findByUsername(username)
	            .orElseThrow(() -> {
	            	CurrentAuthUsernameHolder.clear();
	                log.warn("Authentication failed: user '{}' not found in Spring MySQL", username);
	                return new UsernameNotFoundException("User not found: " + username);
	            });

	        log.debug("Loaded user '{}' | system={} | tenant={} | legacyId={}",
	            user.getUsername(), user.getSystemType(), user.getTenantId(), user.getLegacySqliteUserId());

	        return new TenantUserDetails(user);
	}

}
