package com.vn.springsecurity.service.impl;

import com.vn.springsecurity.service.VerificationCodeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDate;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class VerificationCodeServiceImpl implements VerificationCodeService {

    private final RedisTemplate<Object, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;

    private static final int CODE_LENGTH = 6;
    private static final int MAX_ATTEMPTS = 5;
    private static final int CODE_EXPIRATION_MINUTES = 10;
    private static final int MAX_DAILY_CODES = 5;

    @Override
    public String generateOTPCode(String email) {
        log.info("Generating OTP code for email: {}", email);
        // Check the number of codes generated for the day
        String dailyCountKey = "daily_count:" + email + ":" + LocalDate.now();
        Integer dailyCount = (Integer) redisTemplate.opsForValue().get(dailyCountKey);

        if (dailyCount != null && dailyCount >= MAX_DAILY_CODES) {
            throw new RuntimeException("Exceeded the maximum number of OTP codes allowed for the day");
        }

        // Generate a random OTP code
        String code = generateRandomCode();
        // Hash the code before storing it in Redis
        String hashedCode = passwordEncoder.encode(code);

        // Store the hashed code in Redis with a 10-minute expiration
        String codeKey = "verification_code:" + email;
        redisTemplate.opsForValue().set(codeKey, hashedCode, CODE_EXPIRATION_MINUTES, TimeUnit.MINUTES);

        // Store the number of attempts for this code
        String attemptsKey = "attempts:" + email + ":" + hashedCode;
        redisTemplate.opsForValue().set(attemptsKey, 0, CODE_EXPIRATION_MINUTES, TimeUnit.MINUTES);

        // Increment the daily count of generated codes
        if (dailyCount == null) {
            redisTemplate.opsForValue().set(dailyCountKey, 1, Duration.ofDays(1));
        } else {
            redisTemplate.opsForValue().increment(dailyCountKey);
        }
        return code;
    }

    @Override
    public boolean verifyOTPCode(String email, String code) {
        log.info("Verifying OTP code for email: {}", email);
        // Retrieve the hashed OTP code from Redis
        String codeKey = "verification_code:" + email;
        String hashedStoredCode = (String) redisTemplate.opsForValue().get(codeKey);

        if (hashedStoredCode == null) {
            return false;
        }

        // Retrieve the number of attempts for the hashed code
        String attemptsKey = "attempts:" + email + ":" + hashedStoredCode;
        Integer attempts = (Integer) redisTemplate.opsForValue().get(attemptsKey);

        if (attempts == null) {
            return false;
        }

        if (attempts >= MAX_ATTEMPTS) {
            // Delete the code and attempts if the maximum attempts are exceeded
            redisTemplate.delete(codeKey);
            redisTemplate.delete(attemptsKey);
            throw new RuntimeException("Exceeded the maximum number of attempts");
        }

        // Increment the number of attempts
        redisTemplate.opsForValue().increment(attemptsKey);

        // Verify the code by comparing it with the hashed stored code
        if (passwordEncoder.matches(code, hashedStoredCode)) {
            // Delete the code and attempts upon successful verification
            redisTemplate.delete(codeKey);
            redisTemplate.delete(attemptsKey);
            return true;
        }
        return false;
    }

    private String generateRandomCode() {
        // Generate a random numeric code of the specified length
        SecureRandom random = new SecureRandom();
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < CODE_LENGTH; i++) {
            code.append(random.nextInt(10));
        }
        return code.toString();
    }
}