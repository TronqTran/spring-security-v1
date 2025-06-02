package com.vn.springsecurity.service;

/**
 * The TokenService interface provides methods for managing refresh and access tokens
 * for authentication and authorization purposes. It includes functionalities such as
 * storing, validating, and deleting refresh tokens, as well as managing blocklisted access tokens.
 */
public interface TokenService {

    // === REFRESH TOKEN ===

    /**
     * Stores a refresh token for a specific user along with its associated token ID and time-to-live (TTL) duration.
     *
     * @param username the username of the user to whom the refresh token belongs
     * @param tokenId the unique identifier of the token
     * @param token the refresh token string to be stored
     * @param ttlInSeconds the time-to-live duration of the token, in seconds
     */
    void storeRefreshToken(String username, String tokenId, String token, long ttlInSeconds);

    /**
     * Validates a refresh token associated with a specific user and token ID.
     *
     * @param username the username of the user to whom the refresh token belongs
     * @param tokenId the unique identifier of the token
     * @param token the refresh token string to be validated
     * @return true if the refresh token is valid, false otherwise
     */
    boolean isRefreshTokenValid(String username, String tokenId, String token);

    /**
     * Validates the refresh token associated with a specific user, identified by their username.
     *
     * @param username the username of the user whose refresh token is being validated
     * @param token the refresh token string to be validated
     * @return true if the refresh token is valid, false otherwise
     */
    boolean isRefreshTokenValidByUserId(String username, String token);

    /**
     * Deletes the refresh token associated with the specified username and token ID.
     * This operation ensures that the token can no longer be used for issuing new access tokens,
     * effectively revoking the refresh token's validity.
     *
     * @param username the username of the user to whom the refresh token belongs
     * @param tokenId the unique identifier of the refresh token to be deleted
     */
    void deleteRefreshToken(String username, String tokenId);

    // === ACCESS TOKEN ===

    /**
     * Blocklists an access token, preventing it from being used for further authentication.
     * The token will remain blocklisted for the specified time-to-live (TTL) duration.
     *
     * @param tokenId the unique identifier of the access token to be blocklisted
     * @param ttlInSeconds the time-to-live duration for which the token will remain blocklisted, in seconds
     */
    void blocklistAccessToken(String tokenId, long ttlInSeconds);

    /**
     * Checks whether a given access token, identified by its unique token ID, is blocklisted.
     * Blocklisted tokens are those that are no longer valid for authentication purposes.
     *
     * @param tokenId the unique identifier of the access token to check
     * @return true if the access token is blocklisted, false otherwise
     */
    boolean isAccessTokenBlocklisted(String tokenId);

}

