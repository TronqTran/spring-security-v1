package com.vn.springsecurity.service;

import jakarta.mail.MessagingException;

/**
 * The EmailService interface provides a method for sending email verification codes.
 * Implementations of this interface are responsible for configuring the email sending
 * process and ensuring the designated email and verification code are sent appropriately.
 */
public interface EmailService {
    /**
     * Sends a verification code to the specified email address.
     *
     * @param email the email address to which the verification code will be sent
     * @param code the verification code to be sent to the email address
     * @throws MessagingException if an error occurs while attempting to send the email
     */
    void sendVerificationCode(String email, String code) throws MessagingException;
}
