package com.richardj46.authservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.dto.RegisterRequest;
import com.richardj46.authservice.dto.RegisteredUserResponse;
import com.richardj46.authservice.entity.Role;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.RoleRepository;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.role.RoleNames;
import com.richardj46.authservice.security.DatabaseUserDetailsService;
import com.richardj46.authservice.security.LoginAttemptService;
import com.richardj46.authservice.security.RefreshCookieHelper;
import com.richardj46.authservice.token.JwtService;
import com.richardj46.authservice.token.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private DatabaseUserDetailsService databaseUserDetailsService;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private RefreshCookieHelper refreshCookieHelper;
    @Mock
    private AuditService auditService;
    @Mock
    private LoginAttemptService loginAttemptService;
    @Mock
    private HttpServletRequest httpRequest;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository,
                roleRepository,
                passwordEncoder,
                authenticationManager,
                databaseUserDetailsService,
                jwtService,
                refreshTokenService,
                refreshCookieHelper,
                auditService,
                loginAttemptService
        );
    }

    @Test
    void register_assignsDefaultUserRole() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("New.User@Example.com");
        request.setPassword("Str0ng!Pass");

        Role userRole = new Role();
        userRole.setId(UUID.randomUUID());
        userRole.setName(RoleNames.USER);

        when(userRepository.existsByEmail("new.user@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleNames.USER)).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode("Str0ng!Pass")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID());
            return user;
        });

        RegisteredUserResponse response = authService.register(request, httpRequest);

        assertThat(response.email()).isEqualTo("new.user@example.com");
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getRoles()).extracting(Role::getName).containsExactly(RoleNames.USER);
        assertThat(captor.getValue().isEnabled()).isTrue();
        verify(auditService).record(any(), any(), eq("new.user@example.com"), eq(httpRequest), any());
    }

    @Test
    void register_rejectsDuplicateEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("taken@example.com");
        request.setPassword("Str0ng!Pass");

        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request, httpRequest))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Email already exists");
    }
}
