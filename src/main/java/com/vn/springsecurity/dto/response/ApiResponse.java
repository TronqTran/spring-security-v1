package com.vn.springsecurity.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse <T> {
    @JsonProperty("status")
    private String status; // "success" or "error"

    @JsonProperty("data")
    private T data; // Main data of the response

    @JsonProperty("error")
    private Error error; // Error information (if any)

    @JsonProperty("message")
    private String message; // Message to the client

    @JsonProperty("metadata")
    private Metadata metadata; // Additional metadata (optional)

    // Status enum
    public enum Status {
        SUCCESS,
        ERROR
    }

    // Static factory methods
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .status(Status.SUCCESS.name())
                .data(data)
                .message(message != null ? message : "Request processed successfully")
                .metadata(Metadata.builder()
                        .timestamp(Instant.now().toString())
                        .version("1.0")
                        .build())
                .build();
    }

    public static <T> ApiResponse<T> error(String errorCode, String message, String errorDescription) {
        return ApiResponse.<T>builder()
                .status(Status.ERROR.name())
                .message(message != null ? message : "An error occurred")
                .error(Error.builder()
                        .code(errorCode != null ? errorCode : "unknown_error")
                        .description(errorDescription != null ? errorDescription : "No description provided")
                        .build())
                .build();
    }

    // Inner class cho Error
    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Error {
        @JsonProperty("code")
        private String code; // Error code

        @JsonProperty("description")
        private String description; // Error description
    }

    // Inner class cho Metadata
    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Metadata {
        @JsonProperty("timestamp")
        private String timestamp; // Creation time of the response

        @JsonProperty("version")
        private String version; // Version of the API
    }
}
