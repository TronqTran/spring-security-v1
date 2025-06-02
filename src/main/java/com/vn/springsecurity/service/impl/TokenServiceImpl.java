package com.vn.springsecurity.service.impl;

import com.vn.springsecurity.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";
    private static final String BLOCKLIST_PREFIX = "blocklist:access:";
    private static final String BLOCKLISTED_VALUE = "blocklisted";

    private final RedisTemplate<Object, Object> redisTemplate;

    @Override
    public void storeRefreshToken(String username, String tokenId, String token, long ttlInSeconds) {
        log.info("Storing refresh token for user: {}, tokenId: {}", username, tokenId);
        // Ensure all required parameters are valid and non-empty
        validateInputs(username, tokenId, token);
        validateTTL(ttlInSeconds);

        try {
            // Generate a unique Redis key by combining username and tokenId
            String key = buildRefreshTokenKey(username, tokenId);
            // Create a secure hash of the token for storage
            String hashedToken = hashWithSHA256(token);

            // Persist token with expiration time in a Redis database
            redisTemplate.opsForValue().set(key, hashedToken, ttlInSeconds, TimeUnit.SECONDS);
        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException("Failed to store refresh token", e);
        }
    }

    @Override
    public boolean isRefreshTokenValid(String username, String tokenId, String token) {
        log.info("Validating refresh token for user: {}, tokenId: {}", username, tokenId);
        // Ensure all required authentication parameters are valid
        validateInputs(username, tokenId, token);

        try {
            // Retrieve a stored token from Redis using a composite key
            String key = buildRefreshTokenKey(username, tokenId);
            Object storedValue = redisTemplate.opsForValue().get(key);

            if (storedValue == null) {
                // Token isn't found in storage - considered invalid
                return false;
            }

            // Verify token authenticity by comparing hash values
            String hashedToken = hashWithSHA256(token);
            return storedValue.toString().equals(hashedToken);

        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException("Failed to validate refresh token", e);
        }
    }

    @Override
    public boolean isRefreshTokenValidByUserId(String username, String token) {
        // Validate user credentials without requiring a specific tokenId
        validateInputs(username, "", token);

        try {
            // Search for all active refresh tokens associated with the username
            String pattern = REFRESH_TOKEN_PREFIX + username + ":*";
            Set<Object> keys = Objects.requireNonNullElse(redisTemplate.keys(pattern), Collections.emptySet());

            if (keys.isEmpty()) {
                // User has no active refresh tokens
                return false;
            }

            // Generate a secure hash for token validation
            String hashedToken = hashWithSHA256(token);

            // Validate token against all active tokens for this user
            for (Object key : keys) {
                Object storedValue = redisTemplate.opsForValue().get(key);
                if (storedValue != null && storedValue.toString().equals(hashedToken)) {
                    // Found matching valid token
                    return true;
                }
            }
            // No matching token found among user's active tokens
            return false;
        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException("Failed to validate refresh token by userId", e);
        }
    }

    @Override
    public void deleteRefreshToken(String username, String tokenId) {
        log.info("Deleting refresh token for user: {}, tokenId: {}", username, tokenId);
        // Ensure username and tokenId are valid for token removal
        validateInputs(username, tokenId, "");

        try {
            // Remove the specified refresh token from Redis storage
            String key = buildRefreshTokenKey(username, tokenId);
            redisTemplate.delete(key);
        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException("Failed to delete refresh token", e);
        }
    }

    @Override
    public void blocklistAccessToken(String tokenId, long ttlInSeconds) {
        log.info("Blocklisting access token with tokenId: {}", tokenId);        
        // Validate token parameters before blocklisting
        validateTokenId(tokenId);
        validateTTL(ttlInSeconds);

        try {
            // Add token to blocklist with expiration time
            String key = buildBlocklistKey(tokenId);
            redisTemplate.opsForValue().set(key, BLOCKLISTED_VALUE, ttlInSeconds, TimeUnit.SECONDS);
        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException("Failed to blocklist access token", e);
        }
    }

    @Override
    public boolean isAccessTokenBlocklisted(String tokenId) {
        log.info("Checking blocklist status for tokenId: {}", tokenId);
        // Ensure tokenId is present and valid
        validateTokenId(tokenId);

        try {
            // Check token status in blocklist storage
            String key = buildBlocklistKey(tokenId);
            boolean isBlocklisted = redisTemplate.hasKey(key);
            
            // Log security event if a token is found in the blocklist
            if (isBlocklisted) {
                log.debug("Token is blocklisted: {}", tokenId);
            }
        
            // Return token's blocklist status
            return isBlocklisted;
        } catch (RedisConnectionFailureException e) {
            // Log storage access failure and propagate error
            throw new RuntimeException("Failed to check blocklist status", e);
        }
    }

    private String buildRefreshTokenKey(String username, String tokenId) {
        return REFRESH_TOKEN_PREFIX + username + ":" + tokenId;
    }

    private String buildBlocklistKey(String tokenId) {
        return BLOCKLIST_PREFIX + tokenId;
    }

    private void validateInputs(String username, String tokenId, String token) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username must not be empty");
        }
        if (StringUtils.hasText(tokenId) && tokenId.isEmpty()) {
            throw new IllegalArgumentException("TokenId must not be empty when provided");
        }
        if (StringUtils.hasText(token) && token.isEmpty()) {
            throw new IllegalArgumentException("Token must not be empty when provided");
        }
    }

    private void validateTokenId(String tokenId) {
        if (!StringUtils.hasText(tokenId)) {
            throw new IllegalArgumentException("TokenId must not be empty");
        }
    }

    private void validateTTL(long ttlInSeconds) {
        if (ttlInSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }
    }

    private String hashWithSHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to hash token", e);
            throw new RuntimeException("Error initializing SHA-256 hashing", e);
        }
    }
}