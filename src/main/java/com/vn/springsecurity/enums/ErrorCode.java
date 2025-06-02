package com.vn.springsecurity.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    AUTH_401("auth_401", "Unauthorized"),
    AUTH_403("auth_403", "Forbidden"),
    BAD_REQUEST("bad_request", "Bad request"),
    SERVER_500("server_500", "Internal Server Error"),
    USER_NOT_FOUND("user_not_found", "User not found");
    private final String code;
    private final String message;
}
