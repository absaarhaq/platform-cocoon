package com.talentmatch.platform.identity.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Compatible with Flask's werkzeug.security.generate_password_hash
 * Format: pbkdf2:sha256:{iterations}${salt}${hash}
 */
public class WerkzeugCompatiblePasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		throw new UnsupportedOperationException(
	            "Encoding not supported in Step 1. Use Flask to generate hashes.");
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (rawPassword == null || encodedPassword == null)
			return false;
		
		try {
			// Parse werkzeug format: pbkdf2:sha256:600000$salt$hash
			String[] parts = encodedPassword.split("\\$");
			if(parts.length != 3) return false;
			
			String[] metaParts = parts[0].split(":");
			if (metaParts.length != 3 || !"pbkdf2".equals(metaParts[0]) || !"sha256".equals(metaParts[1])) {
                return false;
            }
			
			int iterations = Integer.parseInt(metaParts[2]);
			byte[] salt = parts[1].getBytes(StandardCharsets.UTF_8);
			 byte[] expectedHash = Base64.getDecoder().decode(padBase64(parts[2]));
			 
			 PBEKeySpec spec = new PBEKeySpec(
		                rawPassword.toString().toCharArray(), salt, iterations, expectedHash.length * 8);
			 SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	         byte[] actualHash = factory.generateSecret(spec).getEncoded();
	         
	         return MessageDigest.isEqual(expectedHash, actualHash);
			
		}catch(Exception e) {
			return false;
		}
	}

	private String padBase64(String base64) {
        int padding = 4 - (base64.length() % 4);
        if (padding > 0 && padding < 4) {
            base64 += "=".repeat(padding);
        }
        return base64;
    }

}
