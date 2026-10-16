package com.talentmatch.platform.identity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.talentmatch.platform.identity.security.TenantUserDetails;
import com.talentmatch.platform.tenant.config.PostAuthRedirectResolver;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
public class RootController {

	private final PostAuthRedirectResolver redirectResolver;

	@GetMapping("/")
	public String root() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		// If authenticated, apply same smart redirect as post-login

		/*
		 * if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof
		 * TenantUserDetails tud) {
		 * 
		 * return switch (tud.getSystemType()) { case "ADMIN" ->
		 * "redirect:/admin/matches"; case "CORP" -> "redirect:/dashboard/corp"; case
		 * "UNIVERSITY" -> "redirect:/dashboard/university"; case "CANDIDATE" ->
		 * tud.isProfileCompleted() ? "redirect:/dashboard/candidate/analysis" :
		 * "redirect:/upload"; default -> "redirect:/auth/login"; }; }
		 */

		if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof TenantUserDetails tud) {
			return redirectResolver.resolve(tud);
		}

		// Not authenticated → login page
		return "redirect:/auth/login";
	}
}
