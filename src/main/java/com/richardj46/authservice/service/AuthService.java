package com.richardj46.authservice.service;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import com.richardj46.authservice.audit.AuditEventType;
import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.dto.LoginRequest;
import com.richardj46.authservice.dto.RegisterRequest;
import com.richardj46.authservice.dto.RegisteredUserResponse;
import com.richardj46.authservice.dto.TokenResponse;
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

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final DatabaseUserDetailsService databaseUserDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshCookieHelper refreshCookieHelper;
    private final AuditService auditService;
    private final LoginAttemptService loginAttemptService;

    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            DatabaseUserDetailsService databaseUserDetailsService,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            RefreshCookieHelper refreshCookieHelper,
            AuditService auditService,
            LoginAttemptService loginAttemptService
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.databaseUserDetailsService = databaseUserDetailsService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.refreshCookieHelper = refreshCookieHelper;
        this.auditService = auditService;
        this.loginAttemptService = loginAttemptService;
    }

    @Transactional
    public RegisteredUserResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmail(email)) {
            throw new IllegalStateException("Email already exists");
        }

        Role userRole = roleRepository.findByName(RoleNames.USER)
                .orElseThrow(() -> new IllegalStateException("Default role ROLE_USER is not configured"));

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        user.setRoles(new HashSet<>(Set.of(userRole)));

        User savedUser = userRepository.save(user);
        auditService.record(
                AuditEventType.REGISTER,
                savedUser.getId(),
                savedUser.getEmail(),
                httpRequest,
                "User registration"
        );
        return new RegisteredUserResponse(savedUser.getId(), savedUser.getEmail());
    }

    public TokenResponse login(
            LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.getPassword())
            );

            loginAttemptService.clearFailedAttempts(email);
            TokenResponse tokens = issueTokens(authentication, response);
            User user = userRepository.findByEmail(email).orElse(null);
            auditService.record(
                    AuditEventType.LOGIN_SUCCESS,
                    user != null ? user.getId() : null,
                    email,
                    httpRequest,
                    "Successful login"
            );
            return tokens;
        } catch (LockedException exception) {
            auditService.record(AuditEventType.LOGIN_LOCKED, null, email, httpRequest, "Account locked");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is temporarily locked");
        } catch (DisabledException exception) {
            auditService.record(AuditEventType.LOGIN_FAILURE, null, email, httpRequest, "Account disabled");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User account is disabled");
        } catch (AuthenticationException exception) {
            boolean locked = loginAttemptService.recordFailedAttempt(email, httpRequest);
            if (locked) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is temporarily locked");
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
    }

    @Transactional
    public TokenResponse refresh(Cookie[] cookies, HttpServletRequest httpRequest, HttpServletResponse response) {
        String rawRefreshToken = refreshCookieHelper.readRefreshCookie(cookies);
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is required");
        }

        var userId = refreshTokenService.rotateRefreshToken(rawRefreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        if (!user.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User account is disabled");
        }
        if (user.isAccountLocked()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is temporarily locked");
        }

        UserDetails userDetails = databaseUserDetailsService.toUserDetails(user);

        String newRefreshToken = refreshTokenService.createRefreshToken(user.getId());
        refreshCookieHelper.setRefreshCookie(response, newRefreshToken);

        String accessToken = jwtService.generateAccessToken(userDetails);
        auditService.record(
                AuditEventType.TOKEN_REFRESH,
                user.getId(),
                user.getEmail(),
                httpRequest,
                "Refresh token rotated"
        );
        return TokenResponse.bearer(accessToken, jwtService.getAccessTokenExpiresInSeconds());
    }

    public void logout(Cookie[] cookies, HttpServletRequest httpRequest, HttpServletResponse response) {
        String rawRefreshToken = refreshCookieHelper.readRefreshCookie(cookies);
        UUID userId = null;
        String email = null;

        if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
            try {
                var token = refreshTokenService.findValidToken(rawRefreshToken);
                userId = token.getUserId();
                email = userRepository.findById(userId).map(User::getEmail).orElse(null);
            } catch (ResponseStatusException ignored) {
                // Invalid/expired token — still clear cookie and audit logout attempt.
            }
            refreshTokenService.revokeRefreshToken(rawRefreshToken);
        }

        refreshCookieHelper.clearRefreshCookie(response);
        auditService.record(AuditEventType.LOGOUT, userId, email, httpRequest, "User logout");
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
