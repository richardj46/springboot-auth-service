package com.richardj46.authservice.dto;

import java.util.UUID;

public record RegisteredUserResponse(UUID id, String email) {
}
