package com.richardj46.authservice.token;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Tries the current signing key first, then previous keys during rotation.
 */
public class RotatingJwtDecoder implements JwtDecoder {

    private final List<JwtDecoder> decoders;

    public RotatingJwtDecoder(List<JwtDecoder> decoders) {
        if (decoders == null || decoders.isEmpty()) {
            throw new IllegalArgumentException("At least one JwtDecoder is required");
        }
        this.decoders = List.copyOf(new ArrayList<>(decoders));
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JwtException lastFailure = null;
        for (JwtDecoder decoder : decoders) {
            try {
                return decoder.decode(token);
            } catch (JwtException exception) {
                lastFailure = exception;
            }
        }
        throw lastFailure != null
                ? lastFailure
                : new JwtException("Failed to decode JWT");
    }
}
