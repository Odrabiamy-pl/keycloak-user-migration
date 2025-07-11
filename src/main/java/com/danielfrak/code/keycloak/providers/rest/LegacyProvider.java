package com.danielfrak.code.keycloak.providers.rest;

import com.danielfrak.code.keycloak.providers.rest.exceptions.RestUserProviderException;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUserService;
import com.danielfrak.code.keycloak.providers.rest.remote.UserModelFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Provides legacy user migration functionality
 */
public class LegacyProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputUpdater,
        CredentialInputValidator,
        UserRegistrationProvider {

    private static final Logger LOG = Logger.getLogger(LegacyProvider.class);
    private static final Set<String> supportedCredentialTypes = Collections.singleton(PasswordCredentialModel.TYPE);
    private final KeycloakSession session;
    private final LegacyUserService legacyUserService;
    private final UserModelFactory userModelFactory;
    private final ComponentModel model;

    public LegacyProvider(KeycloakSession session, LegacyUserService legacyUserService,
                          UserModelFactory userModelFactory, ComponentModel model) {
        this.session = session;
        this.legacyUserService = legacyUserService;
        this.userModelFactory = userModelFactory;
        this.model = model;
    }

    private UserModel getUserModel(RealmModel realm, String username, Supplier<Optional<LegacyUser>> user) {
        return user.get()
                .map(u -> {
                    // Check if user already exists in Keycloak
                    boolean duplicate = userModelFactory.isDuplicateUserId(u, realm);
                    if (duplicate) {
                        return session.users().getUserById(realm, u.getId());
                    } else {
                        return userModelFactory.create(u, realm);
                    }
                })
                .orElseGet(() -> {
                    LOG.warnf("User not found in external repository: %s", username);
                    return null;
                });
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        var userIdentifier = getUserIdentifier(userModel);

        if (!legacyUserService.isPasswordValid(userIdentifier, input.getChallengeResponse())) {
            return false;
        }

        if (passwordDoesNotBreakPolicy(realmModel, userModel, input.getChallengeResponse())) {
            userModel.credentialManager().updateCredential(input);
        } else {
            addUpdatePasswordAction(userModel, userIdentifier);
        }

        return true;
    }

    private String getUserIdentifier(UserModel userModel) {
        var userIdConfig = model.getConfig().getFirst(ConfigurationProperties.USE_USER_ID_FOR_CREDENTIAL_VERIFICATION);
        var useUserId = Boolean.parseBoolean(userIdConfig);
        return useUserId ? userModel.getId() : userModel.getUsername();
    }

    private boolean passwordDoesNotBreakPolicy(RealmModel realmModel, UserModel userModel, String password) {
        PasswordPolicyManagerProvider passwordPolicyManagerProvider = session.getProvider(
                PasswordPolicyManagerProvider.class);
        PolicyError error = passwordPolicyManagerProvider
                .validate(realmModel, userModel, password);

        return error == null;
    }

    private void addUpdatePasswordAction(UserModel userModel, String userIdentifier) {
        if (updatePasswordActionMissing(userModel)) {
            LOG.infof("Could not use legacy password for user %s due to password policy." +
                            " Adding UPDATE_PASSWORD action.",
                    userIdentifier);
            userModel.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }
    }

    private boolean updatePasswordActionMissing(UserModel userModel) {
        return userModel.getRequiredActionsStream()
                .noneMatch(s -> s.contains(UserModel.RequiredAction.UPDATE_PASSWORD.name()));
    }

    @Override
    public boolean supportsCredentialType(String s) {
        return supportedCredentialTypes.contains(s);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return false;
    }

    @Override
    public void close() {
        // Not needed
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        try {
            var ok = legacyUserService.updateCredential(getUserIdentifier(user), input.getChallengeResponse());
            if (!ok) {
                LOG.errorf("Failed to update credential for user: %s", user.getUsername());
                return false;
            }
        } catch (RestUserProviderException e) {
            LOG.errorf("Failed to update credential for user: %s", user.getUsername(), e);
        }

        // In case of successful update, must still return false.
        // Otherwise, Keycloak does not store the password in the credential store.
        // Needs further investigation.
        return false;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        String password = null, firstName = null, lastName = null, provider = null, providerUserId = null;

        // if the user was created by a broker (e.g. Facebook), retrieve the broker context
        AuthenticationSessionModel authSession = this.session.getContext().getAuthenticationSession();
        if (authSession != null && authSession.getAuthNote("broker_context") != null) {
            try {
                SerializedBrokeredIdentityContext brokerContext =
                        SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, "broker_context");

                firstName = brokerContext.getFirstName();
                lastName = brokerContext.getLastName();
                provider = brokerContext.getIdentityProviderId();
                providerUserId = brokerContext.getId();
            } catch (Exception e) {
                LOG.error("Error deserializing broker context", e);
            }
        // otherwise, get the user details from the registration form
        } else {
            firstName = getFormParameter("firstName");
            lastName = getFormParameter("lastName");
            password = getFormParameter("password");
        }

        try {
            var user = legacyUserService.addUser(username, password, firstName, lastName, provider, providerUserId);
            return user.map(legacyUser -> userModelFactory.create(legacyUser, realm)).orElse(null);
        } catch (RestUserProviderException e) {
            LOG.errorf("Failed to add user: %s", username, e);
            return null;
        }
    }

    private String getFormParameter(String parameterName) {
        return this.session.getContext()
            .getHttpRequest()
            .getDecodedFormParameters()
            .getFirst(parameterName);
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        try {
            var ok = legacyUserService.removeUser(getUserIdentifier(user));
            if (!ok) {
                LOG.errorf("Failed to remove user: %s", user.getUsername());
                return false;
            }
        } catch (RestUserProviderException e) {
            LOG.errorf("Failed to remove user: %s", user.getUsername(), e);
            return false;
        }

        severFederationLink(user);
        return true;
    }

    private void severFederationLink(UserModel user) {
        LOG.info("Severing federation link for " + user.getUsername());
        String link = user.getFederationLink();
        if (link != null && !link.isBlank()) {
            user.setFederationLink(null);
        }
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not needed
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realmModel, UserModel userModel) {
        return Stream.empty();
    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String s) {
        throw new UnsupportedOperationException("User lookup by id not implemented");
    }

    @Override
    // Since there is no getUserByBrokerUserId method in the UserLookupProvider,
    // we need to reuse getUserByUsername for this purpose
    public UserModel getUserByUsername(RealmModel realmModel, String providerId) {
        return getUserModel(realmModel, providerId, () -> legacyUserService.findByProviderUserId(providerId));
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String email) {
        return getUserModel(realmModel, email, () -> legacyUserService.findByEmail(email));
    }
}
