package com.richardj46.authservice.controller;

import java.util.List;

import com.richardj46.authservice.dto.AuthenticatedUserResponse;
import com.richardj46.authservice.dto.RegisterRequest;
import com.richardj46.authservice.dto.RegisteredUserResponse;
import com.richardj46.authservice.service.AuthService;

import jakarta.validation.Valid;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public RegisteredUserResponse register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return authService.register(request);
    }

    @GetMapping("/me")
    public AuthenticatedUserResponse currentUser(Authentication authentication) {
        List<String> authorities = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .toList();

        return new AuthenticatedUserResponse(authentication.getName(), authorities);
    }
}
