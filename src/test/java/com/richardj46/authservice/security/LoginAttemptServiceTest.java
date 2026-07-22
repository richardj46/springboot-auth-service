package com.richardj46.authservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.config.SecurityProperties;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditService auditService;

    @Mock
    private HttpServletRequest request;

    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void setUp() {
        SecurityProperties properties = new SecurityProperties();
        properties.setMaxFailedLoginAttempts(5);
        properties.setLockoutDuration(Duration.ofMinutes(15));
        loginAttemptService = new LoginAttemptService(userRepository, properties, auditService);
    }

    @Test
    void recordFailedAttempt_locksAfterMaxAttempts() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setFailedLoginAttempts(4);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean locked = loginAttemptService.recordFailedAttempt("user@example.com", request);

        assertThat(locked).isTrue();
        assertThat(user.getFailedLoginAttempts()).isEqualTo(5);
        assertThat(user.getLockedUntil()).isNotNull();
        verify(userRepository).save(user);
    }

    @Test
    void recordFailedAttempt_doesNotLockBeforeThreshold() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setFailedLoginAttempts(1);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean locked = loginAttemptService.recordFailedAttempt("user@example.com", request);

        assertThat(locked).isFalse();
        assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(user.getLockedUntil()).isNull();
    }

    @Test
    void clearFailedAttempts_resetsCounters() {
        User user = new User();
        user.setEmail("user@example.com");
        user.setFailedLoginAttempts(3);
        user.setLockedUntil(java.time.Instant.now().plusSeconds(60));

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        loginAttemptService.clearFailedAttempts("user@example.com");

        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
        verify(userRepository).save(user);
    }

    @Test
    void clearFailedAttempts_skipsWhenAlreadyClear() {
        User user = new User();
        user.setEmail("user@example.com");
        user.setFailedLoginAttempts(0);

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        loginAttemptService.clearFailedAttempts("user@example.com");

        verify(userRepository, never()).save(eq(user));
    }
}
