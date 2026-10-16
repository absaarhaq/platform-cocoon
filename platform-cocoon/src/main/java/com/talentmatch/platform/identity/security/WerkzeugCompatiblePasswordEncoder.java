package com.talentmatch.platform.identity.security;

import com.talentmatch.platform.integration.client.FlaskDualWriteClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Slf4j
public class WerkzeugCompatiblePasswordEncoder implements PasswordEncoder {

    private final FlaskDualWriteClient flaskClient;

    public WerkzeugCompatiblePasswordEncoder(FlaskDualWriteClient flaskClient) {
        this.flaskClient = flaskClient;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return rawPassword.toString();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) return false;

        try {
            if (encodedPassword.startsWith("scrypt:")) {
                // Scrypt format incompatible with Spring's encoder → delegate to Flask
                log.debug("Scrypt hash detected, delegating validation to Flask");
                // We need username for Flask lookup, but PasswordEncoder interface
                // doesn't provide it. Use ThreadLocal from auth filter.
                String username = CurrentAuthUsernameHolder.getUsername();
                if (username == null) {
                    log.error("Cannot validate scrypt: no username in auth context");
                    return false;
                }
                return flaskClient.validatePasswordViaFlask(username, rawPassword.toString());
                
            } else if (encodedPassword.startsWith("pbkdf2:")) {
                return matchesPbkdf2(rawPassword, encodedPassword);
                
            } else {
                log.warn("Unsupported Werkzeug hash format: {}",
                    encodedPassword.substring(0, Math.min(20, encodedPassword.length())));
                return false;
            }
        } catch (Exception e) {
            log.error("Password matching failed", e);
            return false;
        }
    }

    private boolean matchesPbkdf2(CharSequence rawPassword, String encodedPassword) {
        String[] parts = encodedPassword.split("\\$");
        if (parts.length != 3) return false;

        String[] metaParts = parts[0].split(":");
        if (metaParts.length != 3 || !"pbkdf2".equals(metaParts[0]) || !"sha256".equals(metaParts[1])) {
            return false;
        }

        int iterations = Integer.parseInt(metaParts[2]);
        byte[] salt = parts[1].getBytes(StandardCharsets.UTF_8);
        byte[] expectedHash = Base64.getDecoder().decode(padBase64(parts[2]));

        PBEKeySpec spec = new PBEKeySpec(
            rawPassword.toString().toCharArray(), salt, iterations, expectedHash.length * 8);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] actualHash = factory.generateSecret(spec).getEncoded();
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (Exception e) {
            log.error("PBKDF2 matching failed", e);
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