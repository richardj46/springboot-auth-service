package com.richardj46.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ConfirmPasswordRequest {

    @NotBlank(message = "Current password is required")
    @Size(min = 8, max = 72, message = "Current password must be between 8 and 72 characters")
    private String currentPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }
}
