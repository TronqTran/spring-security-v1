package com.vn.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AuthenticationRequest(
        @NotNull @NotBlank String email,
        @NotNull @NotBlank String password
) {
}
