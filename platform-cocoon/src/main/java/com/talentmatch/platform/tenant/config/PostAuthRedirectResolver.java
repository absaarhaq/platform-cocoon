
package com.talentmatch.platform.tenant.config;

import java.net.URI;

import org.springframework.stereotype.Component;

import com.talentmatch.platform.identity.security.TenantUserDetails;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class PostAuthRedirectResolver {

    private final PostAuthRedirectConfig config;
    private final FlaskProperties flaskProperties;

    public String resolve(TenantUserDetails user) {
        String systemType = user.getSystemType();

        // Conditional redirects take precedence.
        if (user.isProfileCompleted()) {
            String key = systemType + ":profileCompleted";
            String url = config.getConditionalRedirects().get(key);

            if (url != null) {
                return toRedirect(substitute(url, user));
            }
        }

        // Fall back to the system's default redirect.
        String url = config.getDefaultRedirects()
                .getOrDefault(systemType, "/auth/login");

        if ("/auth/login".equals(url)) {
            return "redirect:/auth/login";
        }

        return toRedirect(substitute(url, user));
    }

    private String toRedirect(String destination) {    	
    	log.info("Redirect destination received: [{}]", destination);
    	
        if (destination.startsWith("flask:")) {
            String path = destination.substring("flask:".length());

            String baseUrl = flaskProperties.getBaseUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                throw new IllegalStateException(
                        "flask.base-url must be configured");
            }

            return "redirect:" + baseUrl.replaceAll("/+$", "")
                    + "/" + path.replaceAll("^/+", "");
        }

        if (destination.startsWith("spring:")) {
            String path = destination.substring("spring:".length());
            return "redirect:" + path;
        }

        // Explicit external HTTP(S) destinations.
        URI uri;
        try {
            uri = URI.create(destination);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid redirect destination", e);
        }

        String scheme = uri.getScheme();
        if (scheme != null &&
                (scheme.equalsIgnoreCase("http")
                || scheme.equalsIgnoreCase("https"))
                && uri.getHost() != null) {
            return "redirect:" + uri;
        }

        throw new IllegalArgumentException(
                "Unsupported redirect destination: " + destination);
    }

    private String substitute(String url, TenantUserDetails user) {
        return url
                .replace("{tenantId}", safe(user.getTenantId()))
                .replace("{candidateProfileId}",
                        safe(user.getCandidateProfileId()))
                .replace("{userId}",
                        String.valueOf(user.getSpringUserId()));
    }

    private String safe(String value) {
        return value != null ? value : "";
    }
}
