package com.talentmatch.platform.identity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.talentmatch.platform.tenant.filter.TenantContextFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final TenantContextFilter tenantContextFilter;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new WerkzeugCompatiblePasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
		return config.getAuthenticationManager();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http
		 // Disable CSRF for now; re-enable when serving HTML forms from Spring
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(auth -> auth
				// Public endpoints
				.requestMatchers("/auth/login", "/auth/signup", "/auth/register/university").permitAll()
                // Health/readiness probes	
				.requestMatchers("/actuator/health").permitAll()
				// Everything else requires authentication
				.anyRequest().authenticated()
			)
			
			// Session-based auth matching Flask-Login behavior
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.maximumSessions(1)
				.maxSessionsPreventsLogin(false)
			)
			
			// Custom login/logout handled by AuthController, not Spring form login
			.formLogin(form -> form.disable())
			.logout(logout -> logout.disable())
			
			// Register TenantContextFilter AFTER authentication filter
			.addFilterAfter(tenantContextFilter, UsernamePasswordAuthenticationFilter.class);
		
		return http.build();
		
	}

}
