package com.richardj46.authservice.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.richardj46.authservice.config.JwtProperties;
import com.richardj46.authservice.entity.RefreshToken;
import com.richardj46.authservice.repository.RefreshTokenRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setRefreshTtl(Duration.ofDays(30));
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, properties);
    }

    @Test
    void createRefreshToken_storesOnlyHash() {
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UUID userId = UUID.randomUUID();
        String rawToken = refreshTokenService.createRefreshToken(userId);

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());

        RefreshToken saved = captor.getValue();
        assertThat(rawToken).isNotBlank();
        assertThat(saved.getUserId()).isEqualTo(userId);
        assertThat(saved.getTokenHash()).isEqualTo(RefreshTokenService.hashToken(rawToken));
        assertThat(saved.getTokenHash()).isNotEqualTo(rawToken);
        assertThat(saved.getExpiresAt()).isAfter(Instant.now());
    }

    @Test
    void rotateRefreshToken_revokesExistingAndReturnsUserId() {
        UUID userId = UUID.randomUUID();
        String rawToken = "raw-refresh-token";
        RefreshToken existing = new RefreshToken();
        existing.setUserId(userId);
        existing.setTokenHash(RefreshTokenService.hashToken(rawToken));
        existing.setExpiresAt(Instant.now().plusSeconds(3600));

        when(refreshTokenRepository.findByTokenHash(existing.getTokenHash())).thenReturn(Optional.of(existing));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UUID result = refreshTokenService.rotateRefreshToken(rawToken);

        assertThat(result).isEqualTo(userId);
        assertThat(existing.getRevokedAt()).isNotNull();
    }

    @Test
    void findValidToken_rejectsExpiredToken() {
        String rawToken = "expired-token";
        RefreshToken existing = new RefreshToken();
        existing.setTokenHash(RefreshTokenService.hashToken(rawToken));
        existing.setExpiresAt(Instant.now().minusSeconds(60));

        when(refreshTokenRepository.findByTokenHash(existing.getTokenHash())).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> refreshTokenService.findValidToken(rawToken))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Invalid or expired refresh token");
    }

    @Test
    void hashToken_isDeterministicSha256Hex() {
        String hash = RefreshTokenService.hashToken("abc");
        assertThat(hash).hasSize(64);
        assertThat(hash).isEqualTo(RefreshTokenService.hashToken("abc"));
        assertThat(hash).isNotEqualTo(RefreshTokenService.hashToken("abcd"));
    }
}
