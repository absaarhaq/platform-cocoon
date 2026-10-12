package com.talentmatch.platform.identity.dto;

import jakarta.validation.constraints.*;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {

	@NotBlank(message = "Username is required")
    @Size(min = 3, message = "Username must be at least 3 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;

    @NotBlank(message = "Please confirm your password")
    private String confirmPassword;

    @NotBlank(message = "Role is required")
    @Pattern(regexp = "^(candidate|corp)$", message = "Invalid role selected")
    private String role;

    // Optional: only validated when role=corp via controller logic
    private String companyName;

    public boolean isPasswordMatch() {
        return password != null && password.equals(confirmPassword);
    }
}
