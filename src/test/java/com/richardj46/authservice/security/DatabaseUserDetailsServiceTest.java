package com.richardj46.authservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.richardj46.authservice.entity.Role;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.role.RoleNames;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class DatabaseUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    private DatabaseUserDetailsService userDetailsService;

    @BeforeEach
    void setUp() {
        userDetailsService = new DatabaseUserDetailsService(userRepository);
    }

    @Test
    void loadUserByUsername_normalizesEmailAndMapsRoles() {
        Role role = new Role();
        role.setName(RoleNames.USER);

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setPassword("hashed");
        user.setEnabled(true);
        user.setRoles(Set.of(role));

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        UserDetails details = userDetailsService.loadUserByUsername("  User@Example.com ");

        assertThat(details.getUsername()).isEqualTo("user@example.com");
        assertThat(details.getPassword()).isEqualTo("hashed");
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .containsExactly(RoleNames.USER);
    }

    @Test
    void toUserDetails_marksLockedAndDisabledAccounts() {
        User user = new User();
        user.setEmail("locked@example.com");
        user.setPassword("hashed");
        user.setEnabled(false);
        user.setLockedUntil(Instant.now().plusSeconds(600));
        user.setRoles(Set.of());

        UserDetails details = userDetailsService.toUserDetails(user);

        assertThat(details.isEnabled()).isFalse();
        assertThat(details.isAccountNonLocked()).isFalse();
    }

    @Test
    void loadUserByUsername_throwsWhenMissing() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("missing@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
