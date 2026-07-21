package com.richardj46.authservice.service;

import java.util.Locale;

import com.richardj46.authservice.dto.LoginRequest;
import com.richardj46.authservice.dto.RegisterRequest;
import com.richardj46.authservice.dto.RegisteredUserResponse;
import com.richardj46.authservice.dto.TokenResponse;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.security.RefreshCookieHelper;
import com.richardj46.authservice.token.JwtService;
import com.richardj46.authservice.token.RefreshTokenService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;


@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshCookieHelper refreshCookieHelper;


    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            RefreshCookieHelper refreshCookieHelper
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.refreshCookieHelper = refreshCookieHelper;
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

    public TokenResponse login(LoginRequest request, HttpServletResponse response) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.getPassword())
        );

        return issueTokens(authentication, response);
    }

    public TokenResponse refresh(Cookie[] cookies, HttpServletResponse response) {
        String rawRefreshToken = refreshCookieHelper.readRefreshCookie(cookies);
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is required");
        }

        var userId = refreshTokenService.rotateRefreshToken(rawRefreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities("ROLE_USER")
                .build();

        String newRefreshToken = refreshTokenService.createRefreshToken(user.getId());
        refreshCookieHelper.setRefreshCookie(response, newRefreshToken);

        String accessToken = jwtService.generateAccessToken(userDetails);
        return TokenResponse.bearer(accessToken, jwtService.getAccessTokenExpiresInSeconds());
    }

    public void logout(Cookie[] cookies, HttpServletResponse response) {
        String rawRefreshToken = refreshCookieHelper.readRefreshCookie(cookies);
        if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
            refreshTokenService.revokeRefreshToken(rawRefreshToken);
        }
        refreshCookieHelper.clearRefreshCookie(response);
    }

    private TokenResponse issueTokens(Authentication authentication, HttpServletResponse response) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        String rawRefreshToken = refreshTokenService.createRefreshToken(user.getId());
        refreshCookieHelper.setRefreshCookie(response, rawRefreshToken);

        String accessToken = jwtService.generateAccessToken(userDetails);
        return TokenResponse.bearer(accessToken, jwtService.getAccessTokenExpiresInSeconds());
    }
}
