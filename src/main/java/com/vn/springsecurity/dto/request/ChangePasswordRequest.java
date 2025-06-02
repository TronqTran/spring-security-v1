package com.vn.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ChangePasswordRequest(
        @NotNull @NotBlank String currentPassword,
        @NotNull @NotBlank String newPassword,
        @NotNull @NotBlank String confirmPassword) {
    public ChangePasswordRequest {
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }
    }
}
