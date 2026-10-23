package io.certlocker.trustclient.client;

import io.certlocker.trustclient.error.CLErrorException;
import io.certlocker.trustclient.error.TrustError;
import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.service.MapperService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;
import java.util.Optional;

/**
 * Client for a Certlocker Trust service.
 * <p>
 * {@code get} methods return the asset record as JSON. {@code fetch} methods return the asset contents.
 * Create an instance with {@link #builder()} or {@link TrustClientBuilder}.
 *
 * @author dhudson
 * 22/10/2026 - 13:00
 */
public final class TrustClient implements AutoCloseable {

    private static final String APPLICATION_JSON = "application/json";
    private static final String TEXT_PLAIN = "text/plain";

    private static final String TRUST_BASE = "/rest/api";
    private static final String CERT_BASE = TRUST_BASE + "/v1/cert";
    private static final String CERT_GET = CERT_BASE + "/get";
    private static final String CERT_FETCH = CERT_BASE + "/fetch";
    private static final String CERT_BUNDLE = CERT_BASE + "/fetch-bundle";
    private static final String SECRET_BASE = TRUST_BASE + "/v1/secret";
    private static final String SECRET_GET = SECRET_BASE + "/get";
    private static final String SECRET_FETCH = SECRET_BASE + "/fetch";
    private static final String TOKEN_BASE = TRUST_BASE + "/v1/token";
    private static final String TOKEN_GET = TOKEN_BASE + "/get";

    private final URI theUrl;
    private final String theApiKey;
    private final HttpClient theClient;

    TrustClient(URI url, String apiKey, HttpClient httpClient) {
        theUrl = Objects.requireNonNull(url, "url");
        theApiKey = Objects.requireNonNull(apiKey, "apiKey");
        theClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    /**
     * Returns a new builder with the {@linkplain TrustClientBuilder#DEFAULT_CONNECT_TIMEOUT default connect timeout}.
     *
     * @return a new builder
     */
    public static TrustClientBuilder builder() {
        return new TrustClientBuilder();
    }

    /**
     * Returns the Trust base URL.
     *
     * @return Trust base URL
     */
    public URI getUrl() {
        return theUrl;
    }

    /**
     * Returns the API key sent as the {@code x-api-token} header.
     *
     * @return API key
     */
    public String getApiKey() {
        return theApiKey;
    }

    /**
     * Returns the HTTP client used for requests.
     *
     * @return HTTP client
     */
    public HttpClient getHttpClient() {
        return theClient;
    }

    /**
     * Closes the underlying HTTP client.
     */
    @Override
    public void close() {
        theClient.close();
    }

    private HttpRequest request(String url, String param, String mediaType) {
        String requestUrl = theUrl + url;
        if (param != null) {
            requestUrl += "/" + param;
        }

        return HttpRequest.newBuilder()
                .uri(URI.create(requestUrl))
                .header("x-api-token", theApiKey)
                .header("content-type", mediaType)
                .header("accept", mediaType)
                .GET()
                .build();
    }

    private String processRequest(String url, String param, String mediaType) throws TrustClientException {
        HttpRequest request = request(url, param, mediaType);
        try {
            HttpResponse<String> response = theClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return response.body();
            }

            TrustError error = null;
            Optional<String> className = response.headers().firstValue("x-body-type");
            if (className.isPresent()) {
                if (className.get().equals("certlocker.gateway.api.model.ErrorDTO")) {
                    error = MapperService.getMapper().readValue(response.body(), TrustError.class);
                }
                if (className.get().equals("certlocker.core.exceptions.CLErrorException")) {
                    CLErrorException clError = MapperService.getMapper().readValue(response.body(), CLErrorException.class);
                    error = new TrustError();
                    if (clError != null) {
                        error.setErrorMessage(clError.getError().getMessage());
                    }
                }
            }

            if (error == null) {
                error = new TrustError();
                error.setErrorMessage("Unknown error");
            }

            error.setHttpStatus(response.statusCode());
            throw new TrustClientException(error);

        } catch (IOException | InterruptedException ex) {
            throw new TrustClientException(ex.getMessage(), ex);
        }
    }

    /**
     * Returns the secret record for {@code secretId} as JSON.
     * <p>
     * This is the data regarding the asset. Use {@link #fetchSecret(String)} for the secret contents.
     *
     * @param secretId secret identifier
     * @return JSON secret record
     * @throws TrustClientException if the request fails
     */
    public String getSecret(String secretId) throws TrustClientException {
        return processRequest(SECRET_GET, secretId, APPLICATION_JSON);
    }

    /**
     * Returns the contents of the secret.
     *
     * @param secretId secret identifier
     * @return secret contents
     * @throws TrustClientException if the request fails
     */
    public String fetchSecret(String secretId) throws TrustClientException {
        return processRequest(SECRET_FETCH, secretId, TEXT_PLAIN);
    }

    /**
     * Returns the certificate record for {@code certificateId} as JSON.
     *
     * @param certificateId certificate identifier
     * @return JSON certificate record
     * @throws TrustClientException if the request fails
     */
    public String getCertificate(String certificateId) throws TrustClientException {
        return processRequest(CERT_GET, certificateId, APPLICATION_JSON);
    }

    /**
     * Returns the certificate contents.
     *
     * @param certificateId certificate identifier
     * @return certificate contents
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificate(String certificateId) throws TrustClientException {
        return processRequest(CERT_FETCH, certificateId, TEXT_PLAIN);
    }

    /**
     * Returns the certificate bundle.
     *
     * @param certificateId certificate identifier
     * @return certificate bundle
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificateBundle(String certificateId) throws TrustClientException {
        return processRequest(CERT_BUNDLE, certificateId, TEXT_PLAIN);
    }

    /**
     * Returns the token record for {@code id} as JSON.
     *
     * @param id token identifier
     * @return JSON token record
     * @throws TrustClientException if the request fails
     */
    public String getToken(String id) throws TrustClientException {
        return processRequest(TOKEN_GET, id, APPLICATION_JSON);
    }
}
