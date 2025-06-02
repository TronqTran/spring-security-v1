package com.vn.springsecurity.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.springsecurity.service.TokenService;
import com.vn.springsecurity.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenService redisTokenService;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String accessToken = request.getHeader("Authorization");
        if (accessToken == null || !accessToken.startsWith("Bearer ")) {
            return;
        }
        accessToken = accessToken.substring(7); // Remove "Bearer " prefix

        String refreshToken;
        try {
            // Parse JSON body to extract "refresh_token"
            Map<String, String> bodyMap = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
            refreshToken = bodyMap.get("refresh_token");
        } catch (IOException e) {
            throw new RuntimeException("Error reading logout request body", e);
        }

        if (refreshToken != null && !refreshToken.isEmpty()) {
            String username = jwtUtil.getSubjectFromToken(accessToken);
            String accessTokenId = jwtUtil.getTokenIdFromToken(accessToken);
            String refreshTokenId = jwtUtil.getTokenIdFromToken(refreshToken);

            // Delete the refresh token
            redisTokenService.deleteRefreshToken(username, refreshTokenId);

            // Blocklist the access token
            long accessTokenTTL = JwtUtil.ACCESS_TOKEN_VALIDITY.getSeconds(); // Set TTL (e.g., 1 hour)
            redisTokenService.blocklistAccessToken(accessTokenId, accessTokenTTL);

            log.info("Successfully logged out user: {}", username);
            // Clear the security context
            SecurityContextHolder.clearContext();
        }
    }
}