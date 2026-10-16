package com.talentmatch.platform.identity.security;

/**
 * ThreadLocal holder for current username during authentication.
 * Set by TenantUserDetailsService before matches() is called.
 * Cleared after authentication completes.
 */
public final class CurrentAuthUsernameHolder {
    private static final ThreadLocal<String> USERNAME = new ThreadLocal<>();

    public static void setUsername(String username) { USERNAME.set(username); }
    public static String getUsername() { return USERNAME.get(); }
    public static void clear() { USERNAME.remove(); }
}