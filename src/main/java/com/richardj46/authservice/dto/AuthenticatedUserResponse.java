package com.richardj46.authservice.dto;

import java.util.List;

public record AuthenticatedUserResponse(String email, List<String> authorities) {
}
