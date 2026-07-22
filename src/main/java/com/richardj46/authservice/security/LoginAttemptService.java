package com.richardj46.authservice.security;

import java.time.Instant;

import com.richardj46.authservice.audit.AuditEventType;
import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.config.SecurityProperties;
import com.richardj46.authservice.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LoginAttemptService {

    private final UserRepository userRepository;
    private final SecurityProperties securityProperties;
    private final AuditService auditService;

    public LoginAttemptService(
            UserRepository userRepository,
            SecurityProperties securityProperties,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.securityProperties = securityProperties;
        this.auditService = auditService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearFailedAttempts(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            if (user.getFailedLoginAttempts() > 0 || user.getLockedUntil() != null) {
                user.resetFailedLoginAttempts();
                userRepository.save(user);
            }
        });
    }

    /**
     * @return {@code true} if the account is now locked
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean recordFailedAttempt(String email, HttpServletRequest httpRequest) {
        return userRepository.findByEmail(email).map(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            boolean locked = attempts >= securityProperties.getMaxFailedLoginAttempts();
            if (locked) {
                user.setLockedUntil(Instant.now().plus(securityProperties.getLockoutDuration()));
                auditService.record(
                        AuditEventType.LOGIN_LOCKED,
                        user.getId(),
                        email,
                        httpRequest,
                        "Locked after " + attempts + " failed attempts"
                );
            } else {
                auditService.record(
                        AuditEventType.LOGIN_FAILURE,
                        user.getId(),
                        email,
                        httpRequest,
                        "Failed login (attempt " + attempts + ")"
                );
            }

            userRepository.save(user);
            return locked;
        }).orElseGet(() -> {
            auditService.record(
                    AuditEventType.LOGIN_FAILURE,
                    null,
                    email,
                    httpRequest,
                    "Failed login (unknown user)"
            );
            return false;
        });
    }
}
