package com.vn.springsecurity.service.impl;

import com.vn.springsecurity.dto.request.ChangePasswordRequest;
import com.vn.springsecurity.dto.request.ResetPasswordRequest;
import com.vn.springsecurity.model.User;
import com.vn.springsecurity.repository.UserRepository;
import com.vn.springsecurity.security.CustomUser;
import com.vn.springsecurity.service.UserService;
import com.vn.springsecurity.service.VerificationCodeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationCodeService verificationCodeService;

    @Override
    public User changePassword(ChangePasswordRequest request, Principal connectedUser) {
        //Check if the user is logged in
        CustomUser customUser = (CustomUser) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();
        User user = customUser.getUser();
        log.info("Starting password change process for user: {}", user.getEmail());

        //Check if the current password is correct
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())){
            throw new IllegalStateException("Incorrect password");
        }

        //Save the new password
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        return userRepository.save(user);
    }

    @Override
    public User resetPassword(ResetPasswordRequest request) {
        log.info("Starting password reset process for email: {}", request.email());

        try {
            // Verify OTP code
            boolean isValid = verificationCodeService.verifyOTPCode(
                    request.email(),
                    request.otpCode()
            );

            if (!isValid) {
                throw new IllegalArgumentException("Invalid verification code");
            }

            // Find and update user
            User user = userRepository.findByEmail(request.email())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            // Update the new password
            user.setPassword(passwordEncoder.encode(request.newPassword()));
            user = userRepository.save(user);
            return user;

        } catch (Exception e) {
            throw new RuntimeException("Error resetting password: " + e.getMessage(), e);
        }
    }
}
