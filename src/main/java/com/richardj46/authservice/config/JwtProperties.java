package com.richardj46.authservice.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    private static final int MIN_SECRET_BYTES = 32;

    private String secret;
    /** Comma-separated previous secrets kept for verification during key rotation. */
    private String previousSecrets = "";
    private String keyId = "current";
    private Duration accessTtl = Duration.ofMinutes(10);
    private Duration refreshTtl = Duration.ofDays(30);
    private String refreshCookieName = "refresh_token";
    private boolean refreshCookieSecure;
    /** Lax | Strict | None */
    private String refreshCookieSameSite = "Lax";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getPreviousSecrets() {
        return previousSecrets;
    }

    public void setPreviousSecrets(String previousSecrets) {
        this.previousSecrets = previousSecrets;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public Duration getAccessTtl() {
        return accessTtl;
    }

    public void setAccessTtl(Duration accessTtl) {
        this.accessTtl = accessTtl;
    }

    public Duration getRefreshTtl() {
        return refreshTtl;
    }

    public void setRefreshTtl(Duration refreshTtl) {
        this.refreshTtl = refreshTtl;
    }

    public String getRefreshCookieName() {
        return refreshCookieName;
    }

    public void setRefreshCookieName(String refreshCookieName) {
        this.refreshCookieName = refreshCookieName;
    }

    public boolean isRefreshCookieSecure() {
        return refreshCookieSecure;
    }

    public void setRefreshCookieSecure(boolean refreshCookieSecure) {
        this.refreshCookieSecure = refreshCookieSecure;
    }

    public String getRefreshCookieSameSite() {
        return refreshCookieSameSite;
    }

    public void setRefreshCookieSameSite(String refreshCookieSameSite) {
        this.refreshCookieSameSite = refreshCookieSameSite;
    }

    public List<String> allSecrets() {
        List<String> secrets = new ArrayList<>();
        if (secret != null && !secret.isBlank()) {
            secrets.add(secret);
        }
        if (previousSecrets != null && !previousSecrets.isBlank()) {
            Arrays.stream(previousSecrets.split(","))
                    .map(String::trim)
                    .filter(value -> !value.isEmpty())
                    .forEach(secrets::add);
        }
        return secrets;
    }

    public void validate() {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "JWT_SECRET must be at least " + MIN_SECRET_BYTES + " bytes (256 bits) for HS256"
            );
        }
        if (refreshCookieSameSite != null
                && "None".equalsIgnoreCase(refreshCookieSameSite)
                && !refreshCookieSecure) {
            throw new IllegalStateException("SameSite=None requires refresh-cookie-secure=true");
        }
    }
}
