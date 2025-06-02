package com.vn.springsecurity.service;

import com.vn.springsecurity.dto.request.AuthenticationRequest;
import com.vn.springsecurity.dto.request.RegisterRequest;
import com.vn.springsecurity.dto.response.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Interface for managing user authentication and registration features.
 * Provides methods to register a new user, authenticate an existing user,
 * and refresh authentication tokens when needed.
 */
public interface AuthenticationService {
    /**
     * Handles the registration of a new user by processing the provided registration details.
     *
     * @param registerRequest the request object containing the user's registration details such as
     *                        email, password, and personal information.
     * @return an {@link AuthenticationResponse} containing authentication details such as access token,
     *         refresh token, token type, token expiration time, and issuance time upon successful registration.
     */
    AuthenticationResponse register(RegisterRequest registerRequest);

    /**
     * Authenticates a user using the provided authentication request details.
     *
     * @param authenticationRequest the request containing the user's email and password.
     * @return an {@link AuthenticationResponse} containing authentication details such as
     *         access token, refresh token, token type, token expiration time, and issuance time upon successful authentication.
     */
    AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest);

    /**
     * Refreshes the authentication token for a user by processing the provided request and response objects.
     * This method is typically used to retrieve a new access token using a valid refresh token.
     *
     * @param request the HTTP servlet request containing the refresh token, typically in the headers or cookies.
     * @param response the HTTP servlet response where the new token information may be included.
     * @return an {@link AuthenticationResponse} containing the refreshed access token, refresh token,
     *         token type, token expiration time, and issuance time upon successful refresh.
     * @throws IOException if an input or output error is detected when handling the request or response.
     */
    AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
