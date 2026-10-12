package com.talentmatch.platform.tenant.filter;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.talentmatch.platform.identity.security.TenantUserDetails;
import com.talentmatch.platform.tenant.model.TenantContext;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TenantContextFilter extends OncePerRequestFilter {

	// ThreadLocal holder accessible throughout request lifecycle
	private static final ThreadLocal<TenantContext> CONTEXT = new ThreadLocal<>();

	public static TenantContext getCurrent() {
		TenantContext ctx = CONTEXT.get();
		if (ctx == null) {
			throw new IllegalStateException("TenantContext not initialized. Is user authenticated?");
		}
		return ctx;
	}

	public static void clear() {
		CONTEXT.remove();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null && auth.getPrincipal() instanceof TenantUserDetails tud) {
				TenantContext ctx = new TenantContext(tud.getSpringUserId(), tud.getLegacySqliteUserId(),
						tud.getTenantId(), tud.getSystemType(), tud.getRole(), tud.isProfileCompleted());
				CONTEXT.set(ctx);
				log.debug("TenantContext set: tenant={} system={} legacyId={}", ctx.getTenantId(), ctx.getSystemType(),
						ctx.getLegacySqliteUserId());
			}
			filterChain.doFilter(request, response);
		} finally {
			clear();
		}

	}

}
