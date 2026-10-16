package com.talentmatch.platform.identity.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.talentmatch.platform.identity.dto.SignupRequest;
import com.talentmatch.platform.identity.entity.PlatformUserEntity;
import com.talentmatch.platform.identity.repository.PlatformUserRepository;
import com.talentmatch.platform.identity.security.TenantUserDetails;
import com.talentmatch.platform.integration.client.FlaskDualWriteClient;
import com.talentmatch.platform.shared.util.CandidateIdGenerator;
import com.talentmatch.platform.tenant.config.PostAuthRedirectConfig;
import com.talentmatch.platform.tenant.config.PostAuthRedirectResolver;
import com.talentmatch.platform.tenant.filter.TenantContextFilter;
import com.talentmatch.platform.tenant.model.TenantContext;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final PlatformUserRepository userRepository;
	private final FlaskDualWriteClient flaskDualWriteClient;
	private final PostAuthRedirectConfig redirectConfig;
	private final PostAuthRedirectResolver redirectResolver;

	// ==================== HTML FORM ENDPOINTS ====================

	@GetMapping("/login")
	public String loginPage(@RequestParam(required = false) String error, @RequestParam(required = false) String logout,
			Model model) {
		if (error != null)
			model.addAttribute("error", "Invalid username or password.");
		if (logout != null)
			model.addAttribute("message", "You have been logged out.");
		return "auth/login";
	}

	@PostMapping("/login")
	public String loginFormSubmit(@RequestParam String username, @RequestParam String password, HttpSession session,
			RedirectAttributes redirectAttrs) {
		log.info("Inside logingFormSubmit -> Trying to login");
		try {
			Authentication auth = authenticateAndSync(username, password, session);
			TenantUserDetails tud = (TenantUserDetails) auth.getPrincipal();
			return redirectResolver.resolve(tud);
		} catch (Exception e) {
			log.warn("❌ Form login failed for '{}': {}", username, e.getMessage());
			redirectAttrs.addFlashAttribute("error", "Invalid username or password.");
			return "redirect:/auth/login?error=true";
		}
	}

	@GetMapping("/signup")
	public String signupPage(Model model) {
		model.addAttribute("signupRequest", new SignupRequest());
		return "auth/signup";
	}

	@PostMapping("/signup")
	public String signupFormSubmit(@Valid @ModelAttribute("signupRequest") SignupRequest req,
			BindingResult bindingResult, HttpSession session, RedirectAttributes redirectAttrs) {
		// Cross-field validations
		if (!req.isPasswordMatch()) {
			bindingResult.rejectValue("confirmPassword", "password.mismatch", "Passwords do not match.");
		}
		if (userRepository.existsByUsername(req.getUsername())) {
			bindingResult.rejectValue("username", "username.exists", "Username already exists.");
		}
		if (userRepository.existsByEmail(req.getEmail())) {
			bindingResult.rejectValue("email", "email.exists", "Email already exists.");
		}
		if ("corp".equals(req.getRole()) && (req.getCompanyName() == null || req.getCompanyName().isBlank())) {
			bindingResult.rejectValue("companyName", "company.required",
					"Company name is required for corporate accounts.");
		}

		if (bindingResult.hasErrors()) {
			return "auth/signup";
		}

		// Build entity with role-specific logic
		PlatformUserEntity user = buildUserFromSignup(req);

		// Generate Werkzeug hash via Flask BEFORE saving to either DB
		String werkzeugHash = flaskDualWriteClient.generateWerkzeugHash(req.getPassword());
		user.setPasswordHash(werkzeugHash);

		// Save to Spring MySQL first (authority)
		user = userRepository.save(user);

		// Dual-write to Flask SQLite
		Integer legacyId = flaskDualWriteClient.createLegacyUser(user, req.getPassword());
		if (legacyId != null) {
			user.setLegacySqliteUserId(legacyId);
			userRepository.save(user);
			log.info("✅ Signup dual-write: springId={} legacyId={}", user.getId(), legacyId);
		} else {
			log.error("❌ Signup dual-write FAILED for '{}'", user.getUsername());
			redirectAttrs.addFlashAttribute("danger", "Account created but legacy sync failed. Contact support.");
			return "redirect:/auth/login";
		}

		// Auto-login after signup
		try {
			Authentication auth = authenticateAndSync(req.getUsername(), req.getPassword(), session);
			redirectAttrs.addFlashAttribute("success", "Welcome! Your account has been created.");
			return redirectResolver.resolve((TenantUserDetails) auth.getPrincipal());
		} catch (Exception e) {
			log.error("Auto-login after signup failed for '{}': {}", req.getUsername(), e.getMessage());
			redirectAttrs.addFlashAttribute("info", "Account created. Please log in.");
			return "redirect:/auth/login";
		}

	}	

	// ==================== JSON API ENDPOINTS (PRESERVED FROM ORIGINAL) ====================

	@PostMapping("/api/login")
	@ResponseBody
	public ResponseEntity<?> loginApi(@Valid @RequestBody LoginRequest req, HttpSession session) {
		try {
			Authentication auth = authenticateAndSync(req.getUsername(), req.getPassword(), session);
			TenantUserDetails tud = (TenantUserDetails) auth.getPrincipal();

			return ResponseEntity.ok(Map.of("message", "Login successful", "username", tud.getUsername(), "systemType",
					tud.getSystemType(), "tenantId", tud.getTenantId(), "profileCompleted", tud.isProfileCompleted(),
					"flaskSessionSynced", true));
		} catch (Exception e) {
			log.warn("❌ API login failed for '{}': {}", req.getUsername(), e.getMessage());
			return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
		}

	}

	@PostMapping("/api/logout")
	@ResponseBody
	public ResponseEntity<?> logoutApi(HttpSession session) {
		String username = session.getAttribute("username") != null ? session.getAttribute("username").toString()
				: "unknown";
		SecurityContextHolder.clearContext();
		session.invalidate();
		log.info("API Logout: user='{}'", username);
		return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
	}

	// ======================== LOGOUT ========================

	@PostMapping("/logout")
	public String logoutForm(HttpSession session, RedirectAttributes redirectAttrs) {
		SecurityContextHolder.clearContext();
		session.invalidate();
		redirectAttrs.addFlashAttribute("message", "You have been logged out.");
		return "redirect:/auth/login?logout=true";
	}

	// ======================== CURRENT USER ========================

	@GetMapping("/me")
	@ResponseBody
	public ResponseEntity<?> me() {
		TenantContext ctx = TenantContextFilter.getCurrent();
		return ResponseEntity.ok(Map.of("springUserId", ctx.getSpringUserId(), "legacySqliteUserId",
				ctx.getLegacySqliteUserId() != null ? ctx.getLegacySqliteUserId() : -1, "username",
				SecurityContextHolder.getContext().getAuthentication().getName(), "tenantId", ctx.getTenantId(),
				"systemType", ctx.getSystemType(), "role", ctx.getRole(), "profileCompleted",
				ctx.isProfileCompleted()));
	}

	// ==================== SHARED INTERNAL LOGIC ====================

	/**
	 * Centralized auth + Flask session bridge. Used by BOTH form and API login.
	 */
	private Authentication authenticateAndSync(String username, String password, HttpSession session) {
		
		log.info("@@@@@@@ inside authenticateAndSync");
		Authentication auth = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(username, password));

		SecurityContextHolder.getContext().setAuthentication(auth);
		session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

		TenantUserDetails tud = (TenantUserDetails) auth.getPrincipal();
		boolean flaskSynced = flaskDualWriteClient.syncFlaskSession(tud.getLegacySqliteUserId());

		if (!flaskSynced) {
			log.warn("Login succeeded for '{}' but Flask session sync FAILED.", tud.getUsername());
		}

		log.info("✅ Login: user='{}' system='{}' tenant='{}' flaskSynced={}", tud.getUsername(), tud.getSystemType(),
				tud.getTenantId(), flaskSynced);

		return auth;
	}

	private PlatformUserEntity buildUserFromSignup(SignupRequest req) {
		PlatformUserEntity user = PlatformUserEntity.builder().username(req.getUsername()).email(req.getEmail())
				.role(req.getRole()).profileCompleted(false).build();

		if ("candidate".equals(req.getRole())) {
			user.setCandidateProfileId(CandidateIdGenerator.generate());
			user.setCompanyName(null);
			user.setTenantId(user.getCandidateProfileId());
			user.setSystemType("CANDIDATE");
		} else if ("corp".equals(req.getRole())) {
			user.setCompanyName(req.getCompanyName());
			user.setCandidateProfileId(null);
			user.setProfileCompleted(true);
			user.setTenantId(req.getCompanyName());
			user.setSystemType("CORP");
		}
		return user;
	}

	private String resolvePostAuthRedirect(TenantUserDetails user) {
		
		String systemType = user.getSystemType();
		
		// Check conditional redirects first
		if(user.isProfileCompleted()) {
			String conditionalKey = systemType + ":profileCompleted";
			String conditionalUrl = redirectConfig.getConditionalRedirects().get(conditionalKey);
			if(conditionalUrl != null) {
				return "redirect:" + substitutePlaceholders(conditionalUrl, user);
			}
		}
		
		String defaultUrl = redirectConfig.getDefaultRedirects().getOrDefault(systemType,"/auth/login");
		return "redirect:" + substitutePlaceholders(defaultUrl, user);
	}
		
	private String substitutePlaceholders(String url, TenantUserDetails user) {
		return url 
			.replace("{tenantId}", safe(user.getTenantId()))
			.replace("{candidateProfileId}", safe(user.getCandidateProfileId()))
			.replace("{userId}", String.valueOf(user.getSpringUserId()));
	}
	
	private String safe(String value) {
	    return value != null ? value : "";
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
