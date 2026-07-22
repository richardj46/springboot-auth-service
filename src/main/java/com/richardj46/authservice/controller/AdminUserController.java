package com.richardj46.authservice.controller;

import java.util.List;
import java.util.UUID;

import com.richardj46.authservice.dto.AdminUserResponse;
import com.richardj46.authservice.dto.AdminUserUpdateRequest;
import com.richardj46.authservice.service.AdminUserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final AdminUserService adminUserService;

    public AdminUserController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping
    public List<AdminUserResponse> listUsers() {
        return adminUserService.listUsers();
    }

    @GetMapping("/{id}")
    public AdminUserResponse getUser(@PathVariable UUID id) {
        return adminUserService.getUser(id);
    }

    @PutMapping("/{id}")
    public AdminUserResponse updateUser(
            @PathVariable UUID id,
            @Valid @RequestBody AdminUserUpdateRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest
    ) {
        return adminUserService.updateUser(id, request, authentication.getName(), httpRequest);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable UUID id,
            Authentication authentication,
            HttpServletRequest httpRequest
    ) {
        adminUserService.deleteUser(id, authentication.getName(), httpRequest);
        return ResponseEntity.noContent().build();
    }
}
