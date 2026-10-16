package com.talentmatch.platform.integration.session;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.talentmatch.platform.identity.controller.AuthController;

import lombok.extern.slf4j.Slf4j;

/**
 * Manages Flask signed-cookie sessions per legacy user.
 * 
 * Responsibilities: - Acquire session cookie via Flask
 * /internal/auth/sync-session - Cache cookies with TTL to handle Flask-side
 * expiry - Invalidate on logout or detected expiry
 * 
 * Does NOT handle HTTP proxying. That is FlaskProxyController's job.
 */
@Slf4j
@Component
public class FlaskSessionManager {

	private final AuthController authController;

	private final RestTemplate restTemplate;
	private final String flaskBaseUrl;
	private final String internalSecret;
	private final long cacheTtlSeconds;

	private final ConcurrentHashMap<Integer, CachedCookie> cookieCache = new ConcurrentHashMap<>();

	private record CachedCookie(String cookieValue, Instant expiresAt) {
		boolean isExpired() {
			return Instant.now().isAfter(expiresAt);
		}
	}

	public FlaskSessionManager(@Value("${flask.base-url}") String flaskBaseUrl,
			@Value("${flask.internal-secret}") String internalSecret,
			@Value("${flask.session-cache-ttl-seconds:1800}") long cacheTtlSeconds, AuthController authController) {
		this.flaskBaseUrl = flaskBaseUrl;
		this.internalSecret = internalSecret;
		this.cacheTtlSeconds = cacheTtlSeconds;
		this.restTemplate = new RestTemplate();
		this.authController = authController;
	}

	/**
	 * Returns valid "session=xxx" cookie string for given legacy user. Fetches
	 * fresh cookie if cache miss or expired. Returns null if acquisition fails.
	 */
	public String getSessionCookie(Integer legacySqliteUserId) {
		if (legacySqliteUserId == null)
			return null;

		CachedCookie cached = cookieCache.get(legacySqliteUserId);
		if (cached != null && !cached.isExpired()) {
			return cached.cookieValue();
		}

		return acquireFreshCookie(legacySqliteUserId);
	}

	/**
	 * Explicitly invalidate cached session (logout, detected expiry).
	 */
	public void invalidate(Integer legacySqliteUserId) {
		if (legacySqliteUserId != null) {
			cookieCache.remove(legacySqliteUserId);
			log.debug("Flask session invalidated for legacy_id={}", legacySqliteUserId);
		}
	}

	/**
	 * Called when proxy receives 401/302-to-login from Flask. Indicates cached
	 * cookie is stale despite TTL not expiring.
	 */
	public void markStale(Integer legacySqliteUserId) {
		invalidate(legacySqliteUserId);
		log.info("Flask session marked stale for legacy_id={} (will re-acquire on next request)", legacySqliteUserId);
	}

	private String acquireFreshCookie(Integer legacySqliteUserId) {
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.set("X-Internal-Secret", internalSecret);

			ResponseEntity<Map> resposne = restTemplate.exchange(flaskBaseUrl + "/auth/internal/auth/sync-session",
					HttpMethod.POST, new HttpEntity<>(Map.of("legacy_sqlite_user_id", legacySqliteUserId), headers),
					Map.class);

			List<String> setCookies = resposne.getHeaders().get("Set-Cookie");
			if (setCookies == null) {
				log.warn("No Set-Cookie header in sync-session response for legacy_id={}", legacySqliteUserId);
				return null;
			}

			for (String raw : setCookies) {
				if (raw.startsWith("session=")) {
					String cookieValue = raw.split(";")[0].trim();
					Instant expiresAt = Instant.now().plusSeconds(cacheTtlSeconds);
					cookieCache.put(legacySqliteUserId, new CachedCookie(cookieValue, expiresAt));
					log.debug("Acquired fresh Flask session for legacy_id={}, TTL={}s", legacySqliteUserId,
							cacheTtlSeconds);
					return cookieValue;
				}
			}

			log.warn("Set-Cookie present but no 'session=' entry for legacy_id={}", legacySqliteUserId);
			return null;
		} catch (Exception e) {
			log.error("Failed to acquire Flask session for legacy_id={}", legacySqliteUserId, e);
			return null;
		}
	}

}
