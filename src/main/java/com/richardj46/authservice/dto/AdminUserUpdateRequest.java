package com.richardj46.authservice.dto;

import java.util.Set;

import com.richardj46.authservice.common.validation.OptionalStrongPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public class AdminUserUpdateRequest {

    @Email(message = "Email must be valid")
    @Size(max = 255, message = "Email must be at most 255 characters")
    private String email;

    private Boolean enabled;

    private Set<String> roles;

    @OptionalStrongPassword
    private String password;

    /** When true, clears failed login attempts and lockout. */
    private Boolean unlock;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getUnlock() {
        return unlock;
    }

    public void setUnlock(Boolean unlock) {
        this.unlock = unlock;
    }
}
