package com.talentmatch.platform.integration.client;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.talentmatch.platform.identity.entity.PlatformUserEntity;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class FlaskDualWriteClient {

	private final RestTemplate restTemplate;
	private final String baseUrl;
	private final String internalSecret;

	public FlaskDualWriteClient(@Value("${flask.base-url}") String baseUrl,
			@Value("${flask.internal-secret}") String internalSecret) {
		this.baseUrl = baseUrl;
		this.internalSecret = internalSecret;
		this.restTemplate = new RestTemplate();
	}

	/**
	 * Creates legacy SQLite user record. Best-effort; failures logged but do not
	 * block Spring signup. Returns legacy_sqlite_user_id on success, null on
	 * failure.
	 */
	public Integer createLegacyUser(PlatformUserEntity springUser, String rawPassword) {

		try {
			HttpHeaders headers = new org.springframework.http.HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.set("X-Internal-Secret", internalSecret);

			Map<String, Object> payload = Map.of("username", springUser.getUsername(), "email", springUser.getEmail(),
					"role", springUser.getRole(), "password_hash", springUser.getPasswordHash(), "candidate_profile_id",
					springUser.getCandidateProfileId() != null ? springUser.getCandidateProfileId() : "",
					"company_name", springUser.getCompanyName() != null ? springUser.getCompanyName() : "",
					"institution_name", springUser.getInstitutionName() != null ? springUser.getInstitutionName() : "",
					"institution_domain",
					springUser.getInstitutionDomain() != null ? springUser.getInstitutionDomain() : "", "department",
					springUser.getDepartment() != null ? springUser.getDepartment() : "", "profile_completed",
					springUser.getProfileCompleted());

			ResponseEntity<Map> response = restTemplate.exchange(baseUrl + "/auth/internal/users/create",
					HttpMethod.POST, new HttpEntity<>(payload, headers), Map.class);

			if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
				Object userId = response.getBody().get("user_id");
				log.info("Flask dual-write succeeded for user {}: legacy_id={}", springUser.getUsername(), userId);
				return ((Number) userId).intValue();
			}
		} catch (Exception e) {
			log.error("Flask dual-write FAILED for user {}. Spring record exists but SQLite may be out of sync.",
					springUser.getUsername(), e);
		}
		return null;
	}

	/**
	 * Syncs Flask-Login session after Spring authentication.
	 */
	public boolean syncFlaskSession(Integer legacySqliteUserId) {
		log.info("@@@@@@@ syncing flask session");
		if (legacySqliteUserId == null) {
			log.warn("Cannot sync Flask session: no legacy_sqlite_user_id mapped");
			return false;
		}

		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.set("X-Internal-Secret", internalSecret);

			Map<String, Object> payload = Map.of("legacy_sqlite_user_id", legacySqliteUserId);

			ResponseEntity<Map> response = restTemplate.exchange(baseUrl + "/auth/internal/auth/sync-session",
					HttpMethod.POST, new HttpEntity<>(payload, headers), Map.class);

			boolean synced = response.getStatusCode().is2xxSuccessful();
			log.debug("Flask session sync for legacy_id={}: {}", legacySqliteUserId, synced);
			return synced;
		} catch (Exception e) {
			log.error("Flask session sync FAILED for legacy_id={}. Legacy Flask routes will return 401.",
					legacySqliteUserId, e);
			return false;
		}
	}

	public String generateWerkzeugHash(String rawPassword) {
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.set("X-Internal-Secret", internalSecret);

			ResponseEntity<Map> response = restTemplate.exchange(baseUrl + "/auth/internal/auth/hash-password",
					HttpMethod.POST, new HttpEntity<>(Map.of("password", rawPassword), headers), Map.class);
			return (String) response.getBody().get("password_hash");
		} catch (Exception e) {
			log.error("Failed to generate Werkzeug hash", e);
			throw new RuntimeException("Cannot create user: hash generation failed", e);
		}
	}
	
	/**
	 * Validates password via Flask when Spring cannot match hash format natively.
	 * Used ONLY for scrypt hashes; pbkdf2 remains native.
	 */
	public boolean validatePasswordViaFlask(String username, String rawPassword) {
	    try {
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_JSON);
	        headers.set("X-Internal-Secret", internalSecret);

	        ResponseEntity<Map> response = restTemplate.exchange(
	            baseUrl + "/auth/internal/auth/validate-password",
	            HttpMethod.POST,
	            new HttpEntity<>(Map.of("username", username, "password", rawPassword), headers),
	            Map.class
	        );
	        
	        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
	            return Boolean.TRUE.equals(response.getBody().get("valid"));
	        }
	        return false;
	    } catch (Exception e) {
	        log.error("Flask password validation failed for '{}'", username, e);
	        return false;
	    }
	}
}
