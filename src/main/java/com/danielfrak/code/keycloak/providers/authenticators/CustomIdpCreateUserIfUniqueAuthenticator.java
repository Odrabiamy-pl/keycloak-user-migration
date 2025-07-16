/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.danielfrak.code.keycloak.providers.authenticators;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

import java.util.List;
import java.util.Map;
import static org.keycloak.broker.provider.AbstractIdentityProvider.BROKER_REGISTERED_NEW_USER;


/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CustomIdpCreateUserIfUniqueAuthenticator extends AbstractIdpAuthenticator {

    private static Logger logger = Logger.getLogger(com.danielfrak.code.keycloak.providers.authenticators.CustomIdpCreateUserIfUniqueAuthenticator.class);


    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
            context.attempted();
            return;
        }

        String username = getUsername(context, serializedCtx, brokerContext);
        if (username == null) {
            ServicesLogger.LOGGER.resetFlow(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        ExistingUserInfo duplication = brokerContext.getIdpConfig().isTransientUsers() ? null : checkExistingUser(context, username, serializedCtx, brokerContext);

        UserModel federatedUser = null;
        if (brokerContext.getIdpConfig().isTransientUsers()) {
            logger.debugf("Transient brokering requested. Recording user details for account '%s' and from identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());

            federatedUser = new LightweightUserAdapter(session, context.getAuthenticationSession().getParentSession().getId());
            federatedUser.setUsername(username);
        } else if (duplication == null) {
            logger.debugf("No duplication detected. Creating account for user '%s' and linking with identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());

            serializedCtx.saveToAuthenticationSession(context.getAuthenticationSession(), "broker_context");
            federatedUser = session.users().addUser(realm, username);
        }

        if (federatedUser != null) {
            federatedUser.setEnabled(true);

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
                if (!UserModel.USERNAME.equalsIgnoreCase(attr.getKey())) {
                    federatedUser.setAttribute(attr.getKey(), attr.getValue());
                }
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            if (config != null && Boolean.parseBoolean(config.getConfig().get(IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION))) {
                logger.debugf("User '%s' required to update password", federatedUser.getUsername());
                federatedUser.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            }

            userRegisteredSuccess(context, federatedUser, serializedCtx, brokerContext);

            context.setUser(federatedUser);
            context.getAuthenticationSession().setAuthNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            logger.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

            // Get the existing user and authenticate them directly, unless VERIFY_IDP_LINK_ACCOUNT is set to true
            UserModel existingUser = context.getSession().users().getUserById(context.getRealm(), duplication.getExistingUserId());
            String verifyIdpLinkAccount = context.getAuthenticationSession().getAuthNote("VERIFY_IDP_LINK_ACCOUNT");
            if (existingUser != null && !Boolean.parseBoolean(verifyIdpLinkAccount)) {
                context.setUser(existingUser);
                context.success();
            } else {
                // Fall back to regular flow if user can't be found
                context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());

                if (context.getExecution().isRequired()) {
                    Response challengeResponse = context.form()
                            .setError(Messages.FEDERATED_IDENTITY_EXISTS, duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                            .createErrorPage(Response.Status.CONFLICT);
                    context.challenge(challengeResponse);
                    context.getEvent()
                            .user(duplication.getExistingUserId())
                            .detail("existing_" + duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                            .removeDetail(Details.AUTH_METHOD)
                            .removeDetail(Details.AUTH_TYPE)
                            .error(Errors.FEDERATED_IDENTITY_EXISTS);
                } else {
                    context.attempted();
                }
            }
        }
    }

    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        // Check for existing user by broker user ID
        if (brokerContext.getId() != null && brokerContext.getIdpConfig() != null) {
            // Try to find user by external broker ID using getUserByUsername,
            // since there is no getUserByBrokerUserId method in the UserLookupProvider
            UserModel existingUser = context.getSession().users().getUserByUsername(context.getRealm(), brokerContext.getId());

            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), "broker.user.id", brokerContext.getId());
            }
        }

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(context.getRealm(), brokerContext.getEmail());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        return null;
    }

    protected String getUsername(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }


    // Empty method by default. This exists, so subclass can override and add callback after new user is registered through social
    protected void userRegisteredSuccess(AuthenticationFlowContext context, UserModel registeredUser, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

}
