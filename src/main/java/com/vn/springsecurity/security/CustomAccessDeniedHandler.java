package com.vn.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.springsecurity.dto.response.ApiResponse;
import com.vn.springsecurity.enums.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        // Set the HTTP status to 403 (Forbidden)
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // Set the response content type to JSON
        response.setContentType("application/json");

        // Create an error response object with the appropriate error code, message, and exception details
        ApiResponse<Object> errorResponse = ApiResponse.error(
                ErrorCode.AUTH_403.getCode(), ErrorCode.AUTH_403.getMessage(), accessDeniedException.getMessage());

        // Write the error response as a JSON string to the response output
        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }
}
