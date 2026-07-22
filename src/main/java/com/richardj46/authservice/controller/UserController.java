package com.richardj46.authservice.controller;

import com.richardj46.authservice.dto.ChangePasswordRequest;
import com.richardj46.authservice.dto.ConfirmPasswordRequest;
import com.richardj46.authservice.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PutMapping("/password")
    public ResponseEntity<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        userService.changePassword(authentication.getName(), request, httpRequest, response);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/disable")
    public ResponseEntity<Void> disableAccount(
            Authentication authentication,
            @Valid @RequestBody ConfirmPasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        userService.disableAccount(authentication.getName(), request, httpRequest, response);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/account")
    public ResponseEntity<Void> deleteAccount(
            Authentication authentication,
            @Valid @RequestBody ConfirmPasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response
    ) {
        userService.deleteAccount(authentication.getName(), request, httpRequest, response);
        return ResponseEntity.noContent().build();
    }
}
