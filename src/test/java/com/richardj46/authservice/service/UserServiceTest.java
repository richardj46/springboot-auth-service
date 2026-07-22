package com.richardj46.authservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.dto.ChangePasswordRequest;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.security.RefreshCookieHelper;
import com.richardj46.authservice.token.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private RefreshCookieHelper refreshCookieHelper;
    @Mock
    private AuditService auditService;
    @Mock
    private HttpServletRequest httpRequest;
    @Mock
    private HttpServletResponse httpResponse;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(
                userRepository,
                passwordEncoder,
                refreshTokenService,
                refreshCookieHelper,
                auditService
        );
    }

    @Test
    void changePassword_updatesHashAndRevokesSessions() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setPassword("old-hash");
        user.setEnabled(true);

        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("OldPass1!");
        request.setNewPassword("NewPass1!");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("OldPass1!", "old-hash")).thenReturn(true);
        when(passwordEncoder.matches("NewPass1!", "old-hash")).thenReturn(false);
        when(passwordEncoder.encode("NewPass1!")).thenReturn("new-hash");

        userService.changePassword("user@example.com", request, httpRequest, httpResponse);

        assertThat(user.getPassword()).isEqualTo("new-hash");
        verify(userRepository).save(user);
        verify(refreshTokenService).revokeAllForUser(user.getId());
        verify(refreshCookieHelper).clearRefreshCookie(httpResponse);
    }

    @Test
    void changePassword_rejectsIncorrectCurrentPassword() {
        User user = new User();
        user.setEmail("user@example.com");
        user.setPassword("old-hash");
        user.setEnabled(true);

        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("WrongPass1!");
        request.setNewPassword("NewPass1!");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("WrongPass1!", "old-hash")).thenReturn(false);

        assertThatThrownBy(() ->
                userService.changePassword("user@example.com", request, httpRequest, httpResponse)
        ).isInstanceOf(ResponseStatusException.class);

        verify(userRepository, never()).save(any());
        verify(refreshTokenService, never()).revokeAllForUser(any());
    }
}
