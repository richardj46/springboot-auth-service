package com.richardj46.authservice.service;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.richardj46.authservice.audit.AuditEventType;
import com.richardj46.authservice.audit.AuditService;
import com.richardj46.authservice.dto.AdminUserResponse;
import com.richardj46.authservice.dto.AdminUserUpdateRequest;
import com.richardj46.authservice.entity.Role;
import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.RoleRepository;
import com.richardj46.authservice.repository.UserRepository;
import com.richardj46.authservice.role.RoleNames;
import com.richardj46.authservice.token.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AdminUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final AuditService auditService;

    public AdminUserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService,
            AuditService auditService
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public List<AdminUserResponse> listUsers() {
        return userRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public AdminUserResponse getUser(UUID id) {
        return toResponse(requireUser(id));
    }

    @Transactional
    public AdminUserResponse updateUser(
            UUID id,
            AdminUserUpdateRequest request,
            String adminEmail,
            HttpServletRequest httpRequest
    ) {
        User user = requireUser(id);
        boolean revokeSessions = false;
        StringBuilder changes = new StringBuilder();

        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            String newEmail = request.getEmail().trim().toLowerCase(Locale.ROOT);
            if (!newEmail.equals(user.getEmail())) {
                if (userRepository.existsByEmail(newEmail)) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
                }
                user.setEmail(newEmail);
                changes.append("email;");
                revokeSessions = true;
            }
        }

        if (request.getEnabled() != null) {
            if (isSelf(user, adminEmail) && Boolean.FALSE.equals(request.getEnabled())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot disable your own account");
            }
            user.setEnabled(request.getEnabled());
            changes.append("enabled=").append(request.getEnabled()).append(';');
            if (!request.getEnabled()) {
                revokeSessions = true;
            }
        }

        if (Boolean.TRUE.equals(request.getUnlock())) {
            user.resetFailedLoginAttempts();
            changes.append("unlock;");
        }

        if (request.getRoles() != null) {
            Set<Role> roles = resolveRoles(request.getRoles());
            if (isSelf(user, adminEmail) && roles.stream().noneMatch(role -> RoleNames.ADMIN.equals(role.getName()))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot remove ROLE_ADMIN from your own account");
            }
            user.setRoles(roles);
            changes.append("roles;");
            revokeSessions = true;
        }

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            changes.append("password;");
            revokeSessions = true;
            auditService.record(
                    AuditEventType.ADMIN_PASSWORD_RESET,
                    user.getId(),
                    user.getEmail(),
                    httpRequest,
                    "Reset by " + adminEmail
            );
        }

        User saved = userRepository.save(user);
        if (revokeSessions) {
            refreshTokenService.revokeAllForUser(saved.getId());
        }

        auditService.record(
                AuditEventType.ADMIN_USER_UPDATE,
                saved.getId(),
                saved.getEmail(),
                httpRequest,
                "Updated by " + adminEmail + ": " + changes
        );
        return toResponse(saved);
    }

    @Transactional
    public void deleteUser(UUID id, String adminEmail, HttpServletRequest httpRequest) {
        User user = requireUser(id);
        if (isSelf(user, adminEmail)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot delete your own account via admin API");
        }

        UUID userId = user.getId();
        String email = user.getEmail();
        auditService.record(
                AuditEventType.ADMIN_USER_DELETE,
                userId,
                email,
                httpRequest,
                "Deleted by " + adminEmail
        );
        refreshTokenService.revokeAllForUser(userId);
        userRepository.delete(user);
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        if (roleNames.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one role is required");
        }

        Set<String> normalized = roleNames.stream()
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .map(name -> name.startsWith("ROLE_") ? name : "ROLE_" + name)
                .collect(Collectors.toCollection(HashSet::new));

        List<Role> found = roleRepository.findByNameIn(normalized);
        if (found.size() != normalized.size()) {
            Set<String> foundNames = found.stream().map(Role::getName).collect(Collectors.toSet());
            Set<String> missing = new HashSet<>(normalized);
            missing.removeAll(foundNames);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown roles: " + missing);
        }
        return new HashSet<>(found);
    }

    private User requireUser(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private static boolean isSelf(User user, String adminEmail) {
        return user.getEmail().equalsIgnoreCase(adminEmail);
    }

    private AdminUserResponse toResponse(User user) {
        List<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .sorted()
                .toList();

        return new AdminUserResponse(
                user.getId(),
                user.getEmail(),
                user.isEnabled(),
                user.isAccountLocked(),
                user.getFailedLoginAttempts(),
                user.getLockedUntil(),
                roles
        );
    }
}
