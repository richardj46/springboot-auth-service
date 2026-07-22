package com.richardj46.authservice.dto;

import com.richardj46.authservice.common.validation.StrongPassword;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ChangePasswordRequest {

    @NotBlank(message = "Current password is required")
    @Size(min = 8, max = 72, message = "Current password must be between 8 and 72 characters")
    private String currentPassword;

    @StrongPassword
    private String newPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
