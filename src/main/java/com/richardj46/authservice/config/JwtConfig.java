package com.richardj46.authservice.config;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.richardj46.authservice.token.RotatingJwtDecoder;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

import jakarta.annotation.PostConstruct;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, CorsProperties.class, SecurityProperties.class})
public class JwtConfig {

    private final JwtProperties jwtProperties;

    public JwtConfig(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @PostConstruct
    void validateJwtProperties() {
        jwtProperties.validate();
    }

    @Bean
    JwtEncoder jwtEncoder(JwtProperties properties) {
        byte[] secret = properties.getSecret().getBytes(StandardCharsets.UTF_8);
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secret)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.HS256)
                .keyID(properties.getKeyId())
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    @Bean
    JwtDecoder jwtDecoder(JwtProperties properties) {
        List<JwtDecoder> decoders = new ArrayList<>();
        for (String secret : properties.allSecrets()) {
            decoders.add(NimbusJwtDecoder.withSecretKey(toSecretKey(secret))
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build());
        }
        return new RotatingJwtDecoder(decoders);
    }

    private static SecretKey toSecretKey(String secret) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }
}
