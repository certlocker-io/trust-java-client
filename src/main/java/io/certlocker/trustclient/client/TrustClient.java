package io.certlocker.trustclient.client;

import io.certlocker.trustclient.auth.AuthCodePrompt;
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

    /** Header for step-up 2FA / accessCode on user-bound tokens (Gateway). */
    public static final String ACCESS_CODE_HEADER = "x-access-code";

    private final URI theUrl;
    private final String theApiKey;
    private final HttpClient theClient;
    private final AuthCodePrompt theAuthCodePrompt;
    private volatile String theAccessCode;

    TrustClient(URI url, String apiKey, HttpClient httpClient) {
        this(url, apiKey, httpClient, null);
    }

    TrustClient(URI url, String apiKey, HttpClient httpClient, AuthCodePrompt authCodePrompt) {
        theUrl = Objects.requireNonNull(url, "url");
        theApiKey = Objects.requireNonNull(apiKey, "apiKey");
        theClient = Objects.requireNonNull(httpClient, "httpClient");
        theAuthCodePrompt = authCodePrompt;
    }

    /**
     * Sets a 2FA / access code for subsequent requests (user-bound tokens).
     */
    public void setAccessCode(String accessCode) {
        theAccessCode = accessCode;
    }

    /**
     * Interactively prompts for a 2FA / access code when a prompt was configured on the builder.
     */
    public void promptForAccessCode(String reason) throws TrustClientException {
        if (theAuthCodePrompt == null) {
            throw new TrustClientException("No AuthCodePrompt configured; call TrustClientBuilder.authCodePrompt(...)");
        }
        try {
            theAccessCode = theAuthCodePrompt.prompt(reason);
        } catch (Exception e) {
            throw new TrustClientException("Failed to read authentication code: " + e.getMessage(), e);
        }
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

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(requestUrl))
                .header("x-api-token", theApiKey)
                .header("content-type", mediaType)
                .header("accept", mediaType);
        if (theAccessCode != null && !theAccessCode.isBlank()) {
            builder.header(ACCESS_CODE_HEADER, theAccessCode);
        }
        return builder.GET().build();
    }

    private String processRequest(String url, String param, String mediaType) throws TrustClientException {
        return processRequest(url, param, mediaType, true);
    }

    private String processRequest(String url, String param, String mediaType, boolean allowPromptRetry)
            throws TrustClientException {
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
                error.setErrorMessage(response.body() != null ? response.body() : "Unknown error");
            }

            error.setHttpStatus(response.statusCode());
            if (allowPromptRetry && theAuthCodePrompt != null && looksLikeStepUp(error.getErrorMessage())) {
                promptForAccessCode(error.getErrorMessage());
                return processRequest(url, param, mediaType, false);
            }
            throw new TrustClientException(error);

        } catch (IOException | InterruptedException ex) {
            throw new TrustClientException(ex.getMessage(), ex);
        }
    }

    private static boolean looksLikeStepUp(String message) {
        if (message == null) {
            return false;
        }
        String m = message.toLowerCase();
        return m.contains("2fa") || m.contains("access code") || m.contains("accesscode")
                || m.contains("verification code") || m.contains("tfa");
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
