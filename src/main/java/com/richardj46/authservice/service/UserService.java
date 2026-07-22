package com.richardj46.authservice.service;

import java.util.Locale;

import com.richardj46.authservice.audit.AuditEventType;
import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.dto.ChangePasswordRequest;
import com.richardj46.authservice.dto.ConfirmPasswordRequest;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.security.RefreshCookieHelper;
import com.richardj46.authservice.token.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final RefreshCookieHelper refreshCookieHelper;
    private final AuditService auditService;

    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService,
            RefreshCookieHelper refreshCookieHelper,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.refreshCookieHelper = refreshCookieHelper;
        this.auditService = auditService;
    }

    @Transactional
    public void changePassword(
            String email,
            ChangePasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        User user = requireEnabledUser(email);
        verifyCurrentPassword(user, request.getCurrentPassword());

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "New password must be different from the current password"
            );
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        refreshTokenService.revokeAllForUser(user.getId());
        refreshCookieHelper.clearRefreshCookie(response);
        auditService.record(
                AuditEventType.PASSWORD_CHANGE,
                user.getId(),
                user.getEmail(),
                httpRequest,
                "Password changed"
        );
    }

    @Transactional
    public void disableAccount(
            String email,
            ConfirmPasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        User user = requireEnabledUser(email);
        verifyCurrentPassword(user, request.getCurrentPassword());

        user.setEnabled(false);
        userRepository.save(user);
        refreshTokenService.revokeAllForUser(user.getId());
        refreshCookieHelper.clearRefreshCookie(response);
        auditService.record(
                AuditEventType.ACCOUNT_DISABLE,
                user.getId(),
                user.getEmail(),
                httpRequest,
                "Account disabled by user"
        );
    }

    @Transactional
    public void deleteAccount(
            String email,
            ConfirmPasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        User user = requireUser(email);
        verifyCurrentPassword(user, request.getCurrentPassword());

        var userId = user.getId();
        var userEmail = user.getEmail();
        auditService.record(
                AuditEventType.ACCOUNT_DELETE,
                userId,
                userEmail,
                httpRequest,
                "Account deleted by user"
        );
        refreshTokenService.revokeAllForUser(userId);
        userRepository.delete(user);
        refreshCookieHelper.clearRefreshCookie(response);
    }

    private User requireEnabledUser(String email) {
        User user = requireUser(email);
        if (!user.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User account is disabled");
        }
        return user;
    }

    private User requireUser(String email) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        return userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private void verifyCurrentPassword(User user, String currentPassword) {
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }
    }
}
