package com.vn.springsecurity.service;

/**
 * The VerificationCodeService interface defines methods for generating and verifying one-time
 * password (OTP) codes. These methods are typically used for email-based verification processes
 * in security-sensitive operations such as authentication and account recovery.
 */
public interface VerificationCodeService {

    /**
     * Generates a one-time password (OTP) code for the specified email address.
     * This method is used to create a unique OTP that can be sent to the user's email
     * for purposes such as verification or authentication.
     *
     * @param email the email address for which the OTP code is to be generated
     * @return a string representing the generated OTP code
     */
    String generateOTPCode(String email);

    /**
     * Verifies the validity of the provided OTP (One-Time Password) code for the specified email address.
     * This method checks whether the OTP code matches the one associated with the email address
     * and ensures it has not expired or been invalidated.
     *
     * @param email the email address for which the OTP code is being verified
     * @param code the OTP code provided for verification
     * @return true if the OTP code is valid for the specified email address, false otherwise
     */
    boolean verifyOTPCode(String email, String code);
}