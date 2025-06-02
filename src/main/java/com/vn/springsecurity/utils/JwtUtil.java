package com.vn.springsecurity.utils;

import com.vn.springsecurity.enums.TokenType;
import com.vn.springsecurity.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    public static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofHours(1);
    public static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofDays(7);
    public static final MacAlgorithm JWT_ALGORITHM = MacAlgorithm.HS256;

    public String generateAccessToken(User user) {
        // Get the current timestamp
        Instant now = Instant.now();

        // Generate a unique token ID
        String tokenId = UUID.randomUUID().toString();

        // Calculate the token's expiration time
        Instant validity = now.plus(ACCESS_TOKEN_VALIDITY.getSeconds(), ChronoUnit.SECONDS);

        // Create a profile map with user details
        Map<String, Object> profile = new HashMap<>();
        profile.put("firstName", user.getFirstName());
        profile.put("lastName", user.getLastName());

        // Get user authorities
        Collection<? extends GrantedAuthority> authorities = user.getRole().getAuthorities();
        List<String> authoritiesList = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        // Build the JWT claims set
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .id(tokenId)
                .issuedAt(now)
                .issuer("http://localhost:8080")
                .expiresAt(validity)
                .subject(user.getEmail())
                .claim("profile", profile)
                .claim("typ", TokenType.BEARER.name())
                .claim("authorities", authoritiesList)
                .build();

        // Create the JWS header with the specified algorithm
        JwsHeader jwsHeader = JwsHeader.with(JWT_ALGORITHM).build();

        // Encode the JWT and return its token value
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet)).getTokenValue();
    }

    public String generateRefreshToken(User user) {
        // Generate the current timestamp
        Instant now = Instant.now();

        // Create a unique token ID
        String tokenId = UUID.randomUUID().toString();

        // Calculate the expiration time for the refresh token
        Instant validity = now.plus(REFRESH_TOKEN_VALIDITY.getSeconds(), ChronoUnit.SECONDS);

        // Build the JWT claims set with token details
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .id(tokenId)
                .issuedAt(now)
                .expiresAt(validity)
                .subject(user.getEmail())
                .issuer("http://localhost:8080")
                .claim("typ", TokenType.REFRESH.name())
                .build();

        // Create the JWS header with the specified algorithm
        JwsHeader jwsHeader = JwsHeader.with(JWT_ALGORITHM).build();

        // Encode the JWT and return its token value
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet)).getTokenValue();
    }

    // Extracts the subject (e.g., user email) from the provided JWT token
    public String getSubjectFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException e) {
            throw new RuntimeException("Cannot get subject from token", e);
        }
    }

    // Extracts the token type (e.g., BEARER or REFRESH) from the provided JWT token
    public String getTokenTypeFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaim("typ");
        } catch (JwtException e) {
            throw new RuntimeException("Cannot get token type", e);
        }
    }

    // Extracts the unique token ID from the provided JWT token
    public String getTokenIdFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getId();
        } catch (JwtException e) {
            throw new RuntimeException("Cannot get token ID", e);
        }
    }

    // Checks if the provided JWT token is expired
    public boolean isTokenExpired(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return Objects.requireNonNull(jwt.getExpiresAt()).isBefore(Instant.now());
        } catch (JwtException e) {
            throw new RuntimeException("Cannot check token expiration", e);
        }
    }
}
