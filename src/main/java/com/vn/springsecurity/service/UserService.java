package com.vn.springsecurity.service;

import com.vn.springsecurity.dto.request.ChangePasswordRequest;
import com.vn.springsecurity.dto.request.ResetPasswordRequest;
import com.vn.springsecurity.model.User;
import org.springframework.security.core.AuthenticationException;

import java.security.Principal;

/**
 * The UserService interface defines the business logic related to user account management,
 * specifically for handling password changes and password resets.
 */
public interface UserService {
    /**
     * Updates the password of the user currently logged in based on the provided change password request.
     * The method verifies the current password, ensures the new and confirm passwords match,
     * and then applies the password change for the specified user.
     *
     * @param request the {@link ChangePasswordRequest} containing the current password,
     *                new password, and confirmation of the new password
     * @param connectedUser the {@link Principal} representing the user who is currently authenticated
     * @return the updated {@link User} entity after the password change
     * @throws IllegalArgumentException if the new password and confirmation password do not match
     * @throws AuthenticationException if the current password provided does not match the user's existing password
     */
    User changePassword(ChangePasswordRequest request, Principal connectedUser);

    /**
     * Resets the password for a user based on the provided reset password request.
     * This method verifies the provided email, OTP code, and ensures the new and confirm passwords match.
     * Once validated, the user's password is updated to the new password.
     *
     * @param request the {@link ResetPasswordRequest} containing the user's email, OTP code,
     *                new password, and confirmed password
     * @return the updated {@link User} entity with the new password applied
     * @throws IllegalArgumentException if the new password and confirm password do not match
     * @throws IllegalArgumentException if the OTP code is invalid or expired
     * @throws IllegalArgumentException if the email is not registered
     */
    User resetPassword(ResetPasswordRequest request);
}
