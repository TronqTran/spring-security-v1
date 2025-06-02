package com.vn.springsecurity.controller;

import com.vn.springsecurity.dto.request.ChangePasswordRequest;
import com.vn.springsecurity.dto.request.ResetPasswordRequest;
import com.vn.springsecurity.dto.response.ApiResponse;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PatchMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Principal connectedUser) {
        User user = userService.changePassword(request, connectedUser);
        return ResponseEntity.ok(ApiResponse.success(user.getEmail(), "Password updated successfully"));
    }

    @PatchMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        User user = userService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.success(user.getEmail(), "Password rested successfully"));
    }
}
