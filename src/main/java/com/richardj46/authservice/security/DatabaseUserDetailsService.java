package com.richardj46.authservice.security;

import java.util.Locale;

import com.richardj46.authservice.entity.Role;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public DatabaseUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));

        return toUserDetails(user);
    }

    public UserDetails toUserDetails(User user) {
        String[] authorities = user.getRoles().stream()
                .map(Role::getName)
                .toArray(String[]::new);

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .disabled(!user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .authorities(authorities)
                .build();
    }
}
