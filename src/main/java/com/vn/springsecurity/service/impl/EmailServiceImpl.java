package com.vn.springsecurity.service.impl;

import com.vn.springsecurity.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender javaMailSender;

    @Override
    public void sendVerificationCode(String email, String code) throws MessagingException {

        log.info("Sending verification code to email: {}", email);
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        helper.setFrom("noreply@company.com");
        helper.setTo(email);
        helper.setSubject("Your Verification Code");

        String htmlContent = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
                <style>
                    body {
                        margin: 0;
                        padding: 0;
                        font-family: 'Helvetica Neue', Arial, sans-serif;
                        background-color: #f0f2f5;
                    }
                    .container {
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        border-radius: 10px;
                        overflow: hidden;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                    }
                    .header {
                        background: linear-gradient(135deg, #6b48ff, #00ddeb);
                        padding: 25px;
                        text-align: center;
                        color: #ffffff;
                    }
                    .header h2 {
                        margin: 0;
                        font-size: 26px;
                        font-weight: 500;
                    }
                    .content {
                        padding: 30px;
                        text-align: center;
                    }
                    .otp-box {
                        font-size: 28px;
                        font-weight: bold;
                        color: #1a1a1a;
                        background-color: #f1faff;
                        padding: 15px 25px;
                        border: 2px dashed #6b48ff;
                        border-radius: 8px;
                        display: inline-block;
                        margin: 20px 0;
                        letter-spacing: 3px;
                    }
                    .content p {
                        font-size: 16px;
                        color: #555555;
                        line-height: 1.6;
                        margin: 10px 0;
                    }
                    .warning {
                        font-size: 14px;
                        color: #888888;
                        margin-top: 20px;
                    }
                    .footer {
                        background-color: #f9fafb;
                        padding: 20px;
                        text-align: center;
                        font-size: 13px;
                        color: #aaaaaa;
                    }
                    .footer a {
                        color: #6b48ff;
                        text-decoration: none;
                    }
                    @media only screen and (max-width: 600px) {
                        .container {
                            margin: 10px;
                        }
                        .content {
                            padding: 20px;
                        }
                        .otp-box {
                            font-size: 24px;
                            padding: 10px 20px;
                        }
                        .header h2 {
                            font-size: 22px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>🔐 Verify Your Email</h2>
                    </div>
                    <div class="content">
                        <p>Hello there,</p>
                        <p>Thank you for choosing our service! Please use the One-Time Password (OTP) below to verify your email address:</p>
                        <div class="otp-box">%s</div>
                        <p>This OTP is valid for <strong>10 minutes</strong>.</p>
                        <p class="warning">If you did not request this verification, please ignore this email or contact our support team.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 Your Company. All rights reserved.</p>
                        <p><a href="#">Contact Support</a> | <a href="#">Visit our website</a></p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(code);

        helper.setText(htmlContent, true);
        javaMailSender.send(mimeMessage);
    }
}
