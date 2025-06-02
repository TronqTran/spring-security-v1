package com.vn.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RegisterRequest(
        @NotNull @NotBlank String email,
        @NotNull @NotBlank String password,
        @NotNull @NotBlank String confirmPassword,
        @NotNull @NotBlank String firstName,
        @NotNull @NotBlank String lastName){

    public RegisterRequest {
        if (!password.equals(confirmPassword)) {
            throw new IllegalArgumentException("Password and confirm password do not match");
        }
    }
}
