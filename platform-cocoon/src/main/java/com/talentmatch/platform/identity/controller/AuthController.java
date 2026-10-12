package com.talentmatch.platform.identity.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentmatch.platform.identity.repository.PlatformUserRepository;
import com.talentmatch.platform.identity.security.TenantUserDetails;
import com.talentmatch.platform.integration.client.FlaskDualWriteClient;
import com.talentmatch.platform.tenant.filter.TenantContextFilter;
import com.talentmatch.platform.tenant.model.TenantContext;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final PlatformUserRepository userRepository;
	private final FlaskDualWriteClient flaskDualWriteClient;
	
	// ======================== LOGIN ========================

	public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpSession session){
		try {
			// 1. Authenticate against Spring MySQL (Werkzeug hash validation)
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
			
			// 2. Establish Spring Security context + session
			SecurityContextHolder.getContext().setAuthentication(auth);
			session.setAttribute("SPRING+SECURITY_CONTEXT", SecurityContextHolder.getContext());
			
			TenantUserDetails tud = (TenantUserDetails)auth.getPrincipal();
			
			// 3. Bridge: create Flask-Login session for legacy routes
			boolean flaskSynced = flaskDualWriteClient.syncFlaskSession(tud.getLegacySqliteUserId());
			if(!flaskSynced) {
				log.warn("Login succeeded for '{}' but Flask session sync FAILED. Legacy routes will 401.", 
	                    tud.getUsername());
			}
			
			log.info("✅ Login successful: user='{}' system='{}' tenant='{}' flaskSynced={}",
	                tud.getUsername(), tud.getSystemType(), tud.getTenantId(), flaskSynced);

			return ResponseEntity.ok(Map.of(
	                "message", "Login successful",
	                "username", tud.getUsername(),
	                "systemType", tud.getSystemType(),
	                "tenantId", tud.getTenantId(),
	                "profileCompleted", tud.isProfileCompleted(),
	                "flaskSessionSynced", flaskSynced
	            ));
		}catch(Exception e) {
			log.warn("❌ Login failed for '{}': {}", req.getUsername(), e.getMessage());
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
        }
		
	}
	
	// ======================== LOGOUT ========================
	
	@PostMapping("/logout")
	public ResponseEntity<?> logout(HttpSession session){
		String username = session.getAttribute("username") !=null ? session.getAttribute("username").toString() : "unknown";
		
		SecurityContextHolder.clearContext();
		session.invalidate();
		
		log.info("Logout: user='{}'", username);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
	}
	
	// ======================== CURRENT USER ========================
	
	@GetMapping("/me")
	public ResponseEntity<?> me(){
		TenantContext ctx = TenantContextFilter.getCurrent();
		return ResponseEntity.ok(Map.of(
				"springUserId", ctx.getSpringUserId(),
				"legacySqliteUserId", ctx.getLegacySqliteUserId() != null ? ctx.getLegacySqliteUserId() : -1,
				"username",SecurityContextHolder.getContext().getAuthentication().getName(),
				"tenantId",ctx.getTenantId(),
				"systemType",ctx.getSystemType(),
				"role",ctx.getRole(),
				"profileCompleted",ctx.isProfileCompleted()				
		));
	}
	
	 // ======================== REQUEST DTOs ========================
	
	@Data
	public static class LoginRequest {
		@NotBlank(message = "Username is required")
		private String username;
		@NotBlank(message = "Password is required")
		private String password;
		
	}
	
}
