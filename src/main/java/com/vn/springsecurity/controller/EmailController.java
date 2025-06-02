package com.vn.springsecurity.controller;

import com.vn.springsecurity.dto.response.ApiResponse;
import com.vn.springsecurity.service.EmailService;
import com.vn.springsecurity.service.VerificationCodeService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/email")
@RequiredArgsConstructor
public class EmailController {

    private final VerificationCodeService verificationCodeService;
    private final EmailService emailService;

    @GetMapping("/request-otp")
    public ResponseEntity<ApiResponse<String>> sendVerificationCode(@RequestParam("email") String email) throws MessagingException {
        String code = verificationCodeService.generateOTPCode(email);
        emailService.sendVerificationCode(email, code);
        return ResponseEntity.ok(ApiResponse.success(email, "Verification code sent successfully"));
    }
}
