package com.danielfrak.code.keycloak.providers.rest.rest.http;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public class HttpClient {
    private static final String BEARER_FORMAT = "Bearer %s";
    private static final String BASIC_AUTH_FORMAT = "Basic %s";
    private static final String USERNAME_PASSWORD_FORMAT = "%s:%s";
    private static final Logger LOG = Logger.getLogger(HttpClient.class);

    private final HttpClientBuilder httpClientBuilder;

    public HttpClient(HttpClientBuilder httpClientBuilder) {
        this.httpClientBuilder = httpClientBuilder;
    }

    public void enableBasicAuth(String basicAuthUser, String basicAuthPassword) {
        if (basicAuthUser != null
                && !basicAuthUser.isBlank()
                && basicAuthPassword != null
                && !basicAuthPassword.isBlank()) {
            String auth = String.format(USERNAME_PASSWORD_FORMAT, basicAuthUser, basicAuthPassword);
            byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
            var authorizationHeader = new BasicHeader(HttpHeaders.AUTHORIZATION,
                    String.format(BASIC_AUTH_FORMAT, new String(encodedAuth, StandardCharsets.ISO_8859_1)));
            httpClientBuilder.setDefaultHeaders(List.of(authorizationHeader));
        }
    }

    public void enableBearerTokenAuth(String token) {
        if (token != null && !token.isBlank()) {
            var authorizationHeader = new BasicHeader(HttpHeaders.AUTHORIZATION, String.format(BEARER_FORMAT, token));
            httpClientBuilder.setDefaultHeaders(List.of(authorizationHeader));
        }
    }

    public HttpResponse get(String uri) {
        var request = new HttpGet(uri);
        return execute(request);
    }

    private HttpResponse execute(HttpUriRequest request) {
        request.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        try (
                CloseableHttpClient closeableHttpClient = httpClientBuilder.build();
                CloseableHttpResponse response = closeableHttpClient.execute(request)
        ) {
            return getHttpResponse(response);
        } catch (IOException e) {
            throw new HttpRequestException(request, e);
        }
    }

    private HttpResponse getHttpResponse(CloseableHttpResponse response) throws IOException {
        int statusCode = response.getStatusLine().getStatusCode();
        String entityAsString = getEntityAsString(response);

        if (statusCode < 200 || statusCode >= 300 && statusCode != 404) {
            StringBuilder responseDetails = new StringBuilder();

            responseDetails.append("status: ").append(response.getStatusLine()).append("; ");
            responseDetails.append("headers: ");
            for (org.apache.http.Header header : response.getAllHeaders()) {
                responseDetails.append(header.getName()).append(": ").append(header.getValue()).append("; ");
            }
            responseDetails.append("body: ").append(entityAsString);

            LOG.errorf("HTTP request failed with %s", responseDetails.toString());
        }

        return new HttpResponse(statusCode, entityAsString);
    }

    private String getEntityAsString(CloseableHttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        Charset encoding = getEncoding(entity);
        return EntityUtils.toString(entity, encoding);
    }

    private Charset getEncoding(HttpEntity entity) {
        return Optional.ofNullable(ContentType.get(entity))
                .map(ContentType::getCharset)
                .orElse(StandardCharsets.UTF_8);
    }

    public HttpResponse post(String uri, String bodyAsJson) {
        var request = new HttpPost(uri);
        var requestEntity = new StringEntity(bodyAsJson, ContentType.APPLICATION_JSON);
        request.setEntity(requestEntity);
        return execute(request);
    }

    public HttpResponse put(String uri, String bodyAsJson) {
        var request = new HttpPut(uri);
        var requestEntity = new StringEntity(bodyAsJson, ContentType.APPLICATION_JSON);
        request.setEntity(requestEntity);
        return execute(request);
    }

    public HttpResponse patch(String uri, String bodyAsJson) {
        var request = new HttpPatch(uri);
        var requestEntity = new StringEntity(bodyAsJson, ContentType.APPLICATION_JSON);
        request.setEntity(requestEntity);
        return execute(request);
    }

    public HttpResponse delete(String uri) {
        var request = new HttpDelete(uri);
        return execute(request);
    }
}