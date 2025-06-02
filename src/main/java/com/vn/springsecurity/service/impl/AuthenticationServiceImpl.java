package com.vn.springsecurity.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.springsecurity.dto.request.AuthenticationRequest;
import com.vn.springsecurity.dto.request.RegisterRequest;
import com.vn.springsecurity.dto.response.AuthenticationResponse;
import com.vn.springsecurity.enums.ErrorCode;
import com.vn.springsecurity.enums.Role;
import com.vn.springsecurity.enums.TokenType;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.repository.UserRepository;
import com.vn.springsecurity.service.AuthenticationService;
import com.vn.springsecurity.service.TokenService;
import com.vn.springsecurity.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final TokenService redisTokenService;
    private final ObjectMapper objectMapper;

    @Override
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        log.info("Registering user with email: {}", registerRequest.email());

        // Check if the email is already registered
        if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
            throw new IllegalStateException("Email already exists");
        }

        // Create a new user entity and save it to the database
        User user = User
                .builder()
                .email(registerRequest.email())
                .firstName(registerRequest.firstName())
                .lastName(registerRequest.lastName())
                .password(passwordEncoder.encode(registerRequest.password()))
                .role(Role.USER)
                .provider("local".toUpperCase())
                .build();
        userRepository.save(user);

        // Generate an access token for the newly registered user
        String accessToken = jwtUtil.generateAccessToken(user);

        // Build and return the authentication response
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .expiresIn(JwtUtil.ACCESS_TOKEN_VALIDITY.getSeconds())
                .issuedAt(Instant.now())
                .tokenType(TokenType.BEARER.name())
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        log.info("Authenticating user with email: {}", authenticationRequest.email());

        // Authenticate the user using the provided email and password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.email(),
                        authenticationRequest.password()
                )
        );

        // Retrieve the user from the database
        User user = userRepository.findByEmail(authenticationRequest.email()).orElseThrow(
                () -> {
                    getError(authenticationRequest.email());
                    return new UsernameNotFoundException(ErrorCode.USER_NOT_FOUND.getMessage());
                }
        );

        // Generate access and refresh tokens for the authenticated user
        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        // Store the refresh token in Redis with a TTL of 3600 seconds
        String userId = user.getEmail();
        String tokenId = jwtUtil.getTokenIdFromToken(refreshToken);
        redisTokenService.storeRefreshToken(userId, tokenId, refreshToken, JwtUtil.REFRESH_TOKEN_VALIDITY.getSeconds());

        // Build and return the authentication response
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(JwtUtil.ACCESS_TOKEN_VALIDITY.getSeconds())
                .issuedAt(Instant.now())
                .tokenType(TokenType.BEARER.name())
                .build();
    }

    @Override
    public AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken;
        try {
            // Parse JSON body to get "refresh_token"
            log.info("Parsing request body to extract refresh token");
            Map<String, String> bodyMap = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
            refreshToken = bodyMap.get("refresh_token");
        } catch (IOException e) {
            log.error("Error reading refresh token request body", e);
            throw new RuntimeException("Error reading refresh token request body", e);
        }

        if (refreshToken != null && !refreshToken.isEmpty()) {
            log.info("Received refresh token: {}", refreshToken);
            String username = jwtUtil.getSubjectFromToken(refreshToken);
            String refreshTokenId = jwtUtil.getTokenIdFromToken(refreshToken);

            // Validate token type
            String tokenType = jwtUtil.getTokenTypeFromToken(refreshToken);
            if (!TokenType.REFRESH.name().equals(tokenType)) {
                log.error("Invalid token type for refresh: {}", tokenType);
                throw new RuntimeException("Invalid token type for refresh");
            }

            // Check if the refresh token is valid
            if (redisTokenService.isRefreshTokenValid(username, refreshTokenId, refreshToken)) {
                log.info("Refresh token is valid for user: {}", username);
                User user = userRepository.findByEmail(username).orElseThrow(() -> {
                    getError(username);
                    return new RuntimeException("User not found");
                });

                // Generate a new access token and refresh token
                log.debug("Generating new tokens for user: {}", username);
                String accessToken = jwtUtil.generateAccessToken(user);
                String newRefreshToken = jwtUtil.generateRefreshToken(user);

                // Delete old refresh token
                log.info("Deleting old refresh token for user: {}", username);
                redisTokenService.deleteRefreshToken(username, refreshTokenId);

                // Store new refresh token in Redis
                log.info("Storing new refresh token for user: {}", username);
                String newRefreshTokenId = jwtUtil.getTokenIdFromToken(newRefreshToken);
                redisTokenService.storeRefreshToken(username, newRefreshTokenId, newRefreshToken, JwtUtil.REFRESH_TOKEN_VALIDITY.getSeconds());

                // Return response
                log.info("Successfully refreshed tokens for user: {}", username);
                return AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(newRefreshToken)
                        .tokenType(TokenType.BEARER.name())
                        .issuedAt(Instant.now())
                        .expiresIn(JwtUtil.ACCESS_TOKEN_VALIDITY.getSeconds())
                        .build();
            } else {
                log.error("Invalid refresh token for user: {}", username);
                throw new RuntimeException("Invalid refresh token");
            }
        }
        log.error("Refresh token is missing in the request");
        throw new RuntimeException("Refresh token is missing");
    }

    private static void getError(String username) {
        log.error("User not found with email: {}", username);
    }
}
