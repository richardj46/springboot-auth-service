package com.richardj46.authservice.security;

import java.time.Duration;

import com.richardj46.authservice.config.JwtProperties;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class RefreshCookieHelper {

    private static final String AUTH_COOKIE_PATH = "/api/auth";

    private final JwtProperties jwtProperties;

    public RefreshCookieHelper(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public void setRefreshCookie(HttpServletResponse response, String rawToken) {
        response.addHeader("Set-Cookie", buildCookie(rawToken, jwtProperties.getRefreshTtl()).toString());
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie", buildCookie("", Duration.ZERO).toString());
    }

    public String readRefreshCookie(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (jwtProperties.getRefreshCookieName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private ResponseCookie buildCookie(String value, Duration maxAge) {
        return ResponseCookie.from(jwtProperties.getRefreshCookieName(), value)
                .httpOnly(true)
                .secure(jwtProperties.isRefreshCookieSecure())
                .sameSite(jwtProperties.getRefreshCookieSameSite())
                .path(AUTH_COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
