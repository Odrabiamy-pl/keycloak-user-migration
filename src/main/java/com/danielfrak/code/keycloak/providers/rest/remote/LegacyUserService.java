package com.danielfrak.code.keycloak.providers.rest.remote;

import java.util.Optional;

/**
 * Interface to be implemented by Legacy user provider.
 */
public interface LegacyUserService {

    /**
     * Find user by email address.
     *
     * @param email email address to search user by.
     * @return Optional of legacy user.
     */
    Optional<LegacyUser> findByEmail(String email);

    /**
     * Find user by username.
     *
     * @param providerUserId providerUserId to search user by.
     * @return Optional of legacy user.
     */
    Optional<LegacyUser> findByProviderUserId(String providerUserId);

    /**
     * Validate given password in legacy user provider.
     *
     * @param username username to validate password for.
     * @param password the password to validate.
     * @return true if password is valid.
     */
    boolean isPasswordValid(String username, String password);

    boolean updateCredential(String username, String password);

    Optional<LegacyUser> addUser(String email, String password, String firstName, String lastName, String provider, String providerUserId);

    boolean removeUser(String username);
}
