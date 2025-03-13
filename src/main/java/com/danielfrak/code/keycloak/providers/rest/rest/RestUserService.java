package com.danielfrak.code.keycloak.providers.rest.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUserService;
import com.danielfrak.code.keycloak.providers.rest.exceptions.RestUserProviderException;
import com.danielfrak.code.keycloak.providers.rest.rest.http.HttpClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.keycloak.common.util.Encode;
import org.keycloak.component.ComponentModel;

import java.io.IOException;
import java.util.Locale;
import java.util.Optional;

import static com.danielfrak.code.keycloak.providers.rest.ConfigurationProperties.*;

public class RestUserService implements LegacyUserService {

    private static final String RECORD_NOT_FOUND_RESP = "record_not_found";

    private final String uri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public RestUserService(ComponentModel model, HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.uri = model.getConfig().getFirst(URI_PROPERTY);
        this.objectMapper = objectMapper;

        configureBasicAuth(model, httpClient);
        configureBearerTokenAuth(model, httpClient);
    }

    private void configureBasicAuth(ComponentModel model, HttpClient httpClient) {
        var basicAuthConfig = model.getConfig().getFirst(API_HTTP_BASIC_ENABLED_PROPERTY);
        var basicAuthEnabled = Boolean.parseBoolean(basicAuthConfig);
        if (basicAuthEnabled) {
            String basicAuthUser = model.getConfig().getFirst(API_HTTP_BASIC_USERNAME_PROPERTY);
            String basicAuthPassword = model.getConfig().getFirst(API_HTTP_BASIC_PASSWORD_PROPERTY);
            httpClient.enableBasicAuth(basicAuthUser, basicAuthPassword);
        }
    }

    private void configureBearerTokenAuth(ComponentModel model, HttpClient httpClient) {
        var tokenAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(API_TOKEN_ENABLED_PROPERTY));
        if (tokenAuthEnabled) {
            String token = model.getConfig().getFirst(API_TOKEN_PROPERTY);
            httpClient.enableBearerTokenAuth(token);
        }
    }

    @Override
    public Optional<LegacyUser> findByEmail(String email) {
        return findLegacyUser(email)
                .filter(u -> equalsCaseInsensitive(email, u.getEmail()));
    }

    private boolean equalsCaseInsensitive(String a, String b) {
        if(a == null || b == null) {
            return false;
        }

        return a.toUpperCase(Locale.ROOT).equals(b.toUpperCase(Locale.ROOT));
    }

    @Override
    public Optional<LegacyUser> findByUsername(String username) {
        return findLegacyUser(username)
                .filter(u -> equalsCaseInsensitive(username, u.getUsername()));
    }

    private Optional<LegacyUser> findLegacyUser(String usernameOrEmail) {
        if (usernameOrEmail != null) {
            usernameOrEmail = Encode.urlEncode(usernameOrEmail);
        }
        var getUsernameUri = String.format("%s/%s", this.uri, usernameOrEmail);
        try {
            var response = this.httpClient.get(getUsernameUri);
            if (response.getCode() != HttpStatus.SC_OK) {
                return Optional.empty();
            }
            var legacyUser = objectMapper.readValue(response.getBody(), LegacyUser.class);
            return Optional.ofNullable(legacyUser);
        } catch (RuntimeException|IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    @Override
    public boolean isPasswordValid(String username, String password) {
        if (username != null) {
            username = Encode.urlEncode(username);
        }
        var passwordValidationUri = String.format("%s/%s", this.uri, username);
        var dto = new UserPasswordDto(password);
        try {
            var json = objectMapper.writeValueAsString(dto);
            var response = httpClient.post(passwordValidationUri, json);
            return response.getCode() == HttpStatus.SC_OK;
        } catch (IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    @Override
    public boolean updateCredential(String username, String password) {
        if (username != null) {
            username = Encode.urlEncode(username);
        }
        var updateCredentialUri = String.format("%s/%s", this.uri, username);
        var dto = new UserPasswordDto(password);
        try {
            var json = objectMapper.writeValueAsString(dto);
            var response = httpClient.patch(updateCredentialUri, json);
            return response.getCode() == HttpStatus.SC_OK;
        } catch (IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    @Override
    public Optional<LegacyUser> addUser(String email, String password, String firstName, String lastName, String picture, String broker_id) {
        var userJson = objectMapper.createObjectNode();
        userJson.put("email", email);
        userJson.put("firstName", firstName);
        userJson.put("lastName", lastName);

        if (password != null) {
            userJson.put("password", password);
        }
        if (picture != null) {
            userJson.put("picture", picture);
        }
        if (broker_id != null) {
            userJson.put("brokerId", broker_id);
        }

        try {
            var json = objectMapper.writeValueAsString(userJson);
            var response = httpClient.put(uri, json);
            if (response.getCode() != HttpStatus.SC_OK) {
                return Optional.empty();
            }
            var legacyUser = objectMapper.readValue(response.getBody(), LegacyUser.class);
            return Optional.of(legacyUser);
        } catch (IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    @Override
    public boolean removeUser(String username) {
        if (username != null) {
            username = Encode.urlEncode(username);
        }
        var removeUserUri = String.format("%s/%s", this.uri, username);
        try {
            var response = httpClient.delete(removeUserUri);
            if (response.getCode() == HttpStatus.SC_NOT_FOUND && response.getBody().contains(RECORD_NOT_FOUND_RESP)) {
                return true;
            }

            return response.getCode() == HttpStatus.SC_OK;
        } catch (RuntimeException e) {
            throw new RestUserProviderException(e);
        }
    }
}
