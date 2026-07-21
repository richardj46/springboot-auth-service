package com.richardj46.authservice.service;

import java.util.Locale;

import com.richardj46.authservice.dto.RegisterRequest;
import com.richardj46.authservice.dto.RegisteredUserResponse;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public RegisteredUserResponse register(RegisterRequest request) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmail(email)) {
            throw new IllegalStateException("Email already exists");
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(
                passwordEncoder.encode(request.getPassword())
        );

        User savedUser = userRepository.save(user);
        return new RegisteredUserResponse(savedUser.getId(), savedUser.getEmail());
    }
}
