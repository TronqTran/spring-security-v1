package com.vn.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.vn.springsecurity.dto.response.AuthenticationResponse;
import com.vn.springsecurity.enums.TokenType;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.repository.UserRepository;
import com.vn.springsecurity.utils.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
       // Log the success of OAuth2 authentication
        log.info(">>> OAuth2AuthenticationSuccessHandler onAuthenticationSuccess is called");

        // Retrieve the authenticated user's details
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        // Fetch the user from the database using their email
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

        // Generate access and refresh tokens for the user
        String token = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        // Set the HTTP response status and content type
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");

        // Build the authentication response object
        AuthenticationResponse authenticationResponse =
                AuthenticationResponse.builder()
                        .accessToken(token)
                        .refreshToken(refreshToken)
                        .issuedAt(Instant.now())
                        .expiresIn(JwtUtil.ACCESS_TOKEN_VALIDITY.getSeconds())
                        .tokenType(TokenType.BEARER.name())
                        .build();

        // Write the authentication response as JSON to the HTTP response
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        response.getWriter().write(mapper.writeValueAsString(authenticationResponse));
    }
}
