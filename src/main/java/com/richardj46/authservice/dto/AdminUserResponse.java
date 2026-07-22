package com.richardj46.authservice.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AdminUserResponse(
        UUID id,
        String email,
        boolean enabled,
        boolean accountLocked,
        int failedLoginAttempts,
        Instant lockedUntil,
        List<String> roles
) {
}
