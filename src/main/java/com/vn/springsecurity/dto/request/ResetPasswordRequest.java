package com.vn.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ResetPasswordRequest(
        @NotNull @NotBlank String email,
        @NotNull @NotBlank String otpCode,
        @NotNull @NotBlank String newPassword,
        @NotNull @NotBlank String confirmPassword
) {
    public ResetPasswordRequest {
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }
    }
}
