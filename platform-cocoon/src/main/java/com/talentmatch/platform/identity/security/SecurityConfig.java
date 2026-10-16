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

import com.talentmatch.platform.integration.client.FlaskDualWriteClient;
import com.talentmatch.platform.tenant.filter.TenantContextFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final TenantContextFilter tenantContextFilter;

	@Bean
	public PasswordEncoder passwordEncoder(FlaskDualWriteClient flaskClient) {
		return new WerkzeugCompatiblePasswordEncoder(flaskClient);
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth.requestMatchers("/", // ← ADD THIS
				"/auth/login", "/auth/signup", "/auth/register/university", "/css/**", "/js/**", "/images/**")
				.permitAll().anyRequest().authenticated())
				.sessionManagement(
						session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).maximumSessions(1))
				.formLogin(form -> form.disable()).logout(logout -> logout.disable())
				.addFilterAfter(tenantContextFilter, UsernamePasswordAuthenticationFilter.class);
		// CSRF enabled by default for Thymeleaf forms
		return http.build();
	}
}
