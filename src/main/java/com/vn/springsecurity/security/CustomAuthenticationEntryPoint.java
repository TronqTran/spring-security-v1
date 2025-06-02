package com.vn.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.springsecurity.dto.response.ApiResponse;
import com.vn.springsecurity.enums.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // Set the HTTP status to 401 (Unauthorized)
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Set the response content type to JSON
        response.setContentType("application/json");

        // Create an error response object with the appropriate error code, message, and exception details
        ApiResponse<Object> errorResponse = ApiResponse.error(
                ErrorCode.AUTH_401.getCode(), ErrorCode.AUTH_401.getMessage(), authException.getMessage());

        // Write the error response as a JSON string to the response output
        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }
}
