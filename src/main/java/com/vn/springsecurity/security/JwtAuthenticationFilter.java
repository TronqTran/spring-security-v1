package com.vn.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.springsecurity.dto.response.ApiResponse;
import com.vn.springsecurity.enums.ErrorCode;
import com.vn.springsecurity.enums.TokenType;
import com.vn.springsecurity.service.TokenService;
import com.vn.springsecurity.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final BearerTokenResolver bearerTokenResolver;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenService redisTokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Skip filtering for authentication endpoints
        if (isAuthEndpoint(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Resolve the JWT from the request
        final String jwt = bearerTokenResolver.resolve(request);
        if (jwt == null || jwt.isEmpty()) {
            // Proceed with the filter chain if no JWT is found
            filterChain.doFilter(request, response);
            return;
        }

        // Check if the token is blocklisted
        String blocklistKey = jwtUtil.getTokenIdFromToken(jwt);
        if (redisTokenService.isAccessTokenBlocklisted(blocklistKey)) {
            // Respond with an error if the token is blocklisted
            writeErrorResponse(response, "Token is blocklisted");
            return;
        }

        try {
            // Validate the token type
            if (!isValidTokenType(jwt, response)) {
                return;
            }
            log.info(">>> [JWT] JwtAuthenticationFilter doFilterInternal is called");

            // Extract the user email from the token
            String userEmail = jwtUtil.getSubjectFromToken(jwt);
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Authenticate the user if not already authenticated
                authenticateUser(jwt, userEmail, request);
            }
        } catch (Exception e) {
            // Handle any exceptions during token validation or authentication
            writeErrorResponse(response, "Invalid token");
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    // Check if the request is for an authentication endpoint
    private boolean isAuthEndpoint(HttpServletRequest request) {
        return request.getServletPath().contains("/api/v1/auth");
    }

    // Validates the token type to ensure it is a BEARER token
    private boolean isValidTokenType(String jwt, HttpServletResponse response) throws IOException {
        String tokenType = jwtUtil.getTokenTypeFromToken(jwt);
        if (!TokenType.BEARER.name().equals(tokenType)) {
            // Respond with an error if the token type is invalid
            writeErrorResponse(response, "Invalid token type");
            return false;
        }
        return true;
    }

    // Authenticates the user by setting the security context with the user's details
    private void authenticateUser(String jwt, String userEmail, HttpServletRequest request) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);
        if (!jwtUtil.isTokenExpired(jwt)) {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
    }

    // Writes an error response with a 401 Unauthorized status and a custom error message
    private void writeErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        ApiResponse<Object> errorResponse = ApiResponse.error(ErrorCode.AUTH_401.getCode(), ErrorCode.AUTH_401.getMessage(), message);
        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }
}