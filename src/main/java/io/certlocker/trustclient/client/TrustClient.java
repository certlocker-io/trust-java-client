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
 * <p>
 * Multi-tenant Gateway paths require {@code accountId}:
 * {@code /rest/api/v1/{resource}/{accountId}/…}.
 *
 * @author dhudson
 * 22/10/2026 - 13:00
 */
public final class TrustClient implements AutoCloseable {

    private static final String APPLICATION_JSON = "application/json";
    private static final String TEXT_PLAIN = "text/plain";

    private static final String TRUST_BASE = "/rest/api/v1";

    /** Header for step-up 2FA / accessCode on user-bound tokens (Gateway). */
    public static final String ACCESS_CODE_HEADER = "x-access-code";
    /** Gateway challenge type when step-up input is required ({@code ACCESS_CODE}/{@code OTP}/{@code EMAIL}). */
    public static final String ACCESS_RESPONSE_HEADER = "x-access-response";
    /** HTTP status Gateway uses for step-up; response body is the prompt text to show. */
    public static final int ACCESS_REQUIRED_STATUS = 401;

    private final URI theUrl;
    private final String theApiToken;
    private final String theAccountId;
    private final HttpClient theClient;
    private final AuthCodePrompt theAuthCodePrompt;
    private volatile String theAccessCode;

    TrustClient(URI url, String apiToken, String accountId, HttpClient httpClient) {
        this(url, apiToken, accountId, httpClient, null);
    }

    TrustClient(URI url, String apiToken, String accountId, HttpClient httpClient, AuthCodePrompt authCodePrompt) {
        theUrl = Objects.requireNonNull(url, "url");
        theApiToken = Objects.requireNonNull(apiToken, "apiToken");
        theAccountId = Objects.requireNonNull(accountId, "accountId");
        theClient = Objects.requireNonNull(httpClient, "httpClient");
        theAuthCodePrompt = authCodePrompt;
    }

    /**
     * Sets a 2FA / access code for subsequent requests (user-bound tokens).
     *
     * @param accessCode code sent as {@link #ACCESS_CODE_HEADER}
     */
    public void setAccessCode(String accessCode) {
        theAccessCode = accessCode;
    }

    /**
     * Interactively prompts for a 2FA / access code when a prompt was configured on the builder.
     *
     * @param reason prompt text shown to the user (often the Gateway response body)
     * @throws TrustClientException if no prompt is configured or prompting fails
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
     * Returns the API token sent as the {@code x-api-token} header.
     *
     * @return API token
     */
    public String getApiToken() {
        return theApiToken;
    }

    /**
     * Returns the account id used in Gateway paths ({@code /v1/{resource}/{accountId}/…}).
     *
     * @return tenant account id
     */
    public String getAccountId() {
        return theAccountId;
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

    private String certPath(String action) {
        return TRUST_BASE + "/cert/" + (theAccountId.isEmpty() ? "" : encode(theAccountId) + "/") + action;
    }

    private String secretPath(String action) {
        return TRUST_BASE + "/secret/" + (theAccountId.isEmpty() ? "" : encode(theAccountId) + "/") + action;
    }

    private String tokenPath(String action) {
        return TRUST_BASE + "/token/" + (theAccountId.isEmpty() ? "" : encode(theAccountId) + "/") + action;
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
    }

    private HttpRequest request(String url, String param, String mediaType) {
        String requestUrl = theUrl + url;
        if (param != null) {
            requestUrl += "/" + encode(param);
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(requestUrl))
                .header("x-api-token", theApiToken)
                .header("User-Agent", "CertLocker-Trust-Java/1.0.5")
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

            Optional<String> accessResponse = response.headers().firstValue(ACCESS_RESPONSE_HEADER);
            boolean stepUp = response.statusCode() == ACCESS_REQUIRED_STATUS || accessResponse.isPresent();
            if (allowPromptRetry && theAuthCodePrompt != null && stepUp) {
                // Server owns the prompt text (plain body on 401); do not invent local reasons.
                String prompt = response.body() != null && !response.body().isBlank()
                        ? response.body().trim()
                        : "Please enter authentication code";
                promptForAccessCode(prompt);
                return processRequest(url, param, mediaType, false);
            }

            throw new TrustClientException(parseError(response));

        } catch (IOException | InterruptedException ex) {
            throw new TrustClientException(ex.getMessage(), ex);
        }
    }

    private static TrustError parseError(HttpResponse<String> response) {
        TrustError error = null;
        Optional<String> className = response.headers().firstValue("x-body-type");
        if (className.isPresent()) {
            try {
                if (className.get().equals("certlocker.gateway.api.model.ErrorDTO")) {
                    error = MapperService.getMapper().readValue(response.body(), TrustError.class);
                }
                if (className.get().equals("certlocker.core.exceptions.CLErrorException")) {
                    CLErrorException clError = MapperService.getMapper().readValue(response.body(), CLErrorException.class);
                    error = new TrustError();
                    if (clError != null && clError.getError() != null) {
                        error.setErrorMessage(clError.getError().getMessage());
                    }
                }
            } catch (RuntimeException ignored) {
                // fall through to body-as-message
            }
        }

        if (error == null) {
            error = new TrustError();
            error.setErrorMessage(response.body() != null && !response.body().isBlank()
                    ? response.body()
                    : "Unknown error");
        }
        error.setHttpStatus(response.statusCode());
        return error;
    }

    /**
     * Returns the secret record for {@code secretId} as JSON.
     * <p>
     * This is the data regarding the asset. Use {@link #fetchSecret(String)} for the secret contents.
     * A {@code null} id requests the secret assigned to this token.
     *
     * @param secretId secret identifier, or {@code null} when the token is assigned to one secret
     * @return JSON secret record
     * @throws TrustClientException if the request fails
     */
    public String getSecret(String secretId) throws TrustClientException {
        if (secretId == null || secretId.isBlank()) {
            var token = MapperService.getMapper().readTree(getToken(theApiToken));
            var id = token.get("secret_id");
            if (id == null) id = token.get("secretId");
            if (id == null || id.isNull() || id.asString().isBlank())
                throw new TrustClientException("API token is not assigned to a secret");
            secretId = id.asString();
        }
        return processRequest(secretPath("get"), secretId, APPLICATION_JSON);
    }

    /**
     * Returns the contents of the secret.
     * A {@code null} id requests the secret assigned to this token.
     *
     * @param secretId secret identifier, or {@code null} when the token is assigned to one secret
     * @return secret contents
     * @throws TrustClientException if the request fails
     */
    public String fetchSecret(String secretId) throws TrustClientException {
        return processRequest(secretPath("fetch"), secretId, TEXT_PLAIN);
    }

    /**
     * Returns the certificate record for {@code certificateId} as JSON.
     * A {@code null} id requests the certificate assigned to this token.
     *
     * @param certificateId CERTIFICATE access-token ID, or {@code null} to use the configured token
     * @return JSON certificate record
     * @throws TrustClientException if the request fails
     */
    public String getCertificate(String certificateId) throws TrustClientException {
        return processRequest(certPath("get"), certificateId == null || certificateId.isBlank() ? theApiToken : certificateId, APPLICATION_JSON);
    }

    /**
     * Returns the certificate contents.
     * A {@code null} id requests the certificate assigned to this token.
     *
     * @param certificateId CERTIFICATE access-token ID, or {@code null} to use the configured token
     * @return certificate contents
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificate(String certificateId) throws TrustClientException {
        return processRequest(certPath("fetch"), certificateId == null || certificateId.isBlank() ? theApiToken : certificateId, TEXT_PLAIN);
    }

    /**
     * Returns the certificate bundle.
     * A {@code null} id requests the certificate assigned to this token.
     *
     * @param certificateId CERTIFICATE access-token ID, or {@code null} to use the configured token
     * @return certificate bundle
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificateBundle(String certificateId) throws TrustClientException {
        return processRequest(certPath("fetch-bundle"), certificateId == null || certificateId.isBlank() ? theApiToken : certificateId, TEXT_PLAIN);
    }

    /**
     * Returns the token record for {@code id} as JSON.
     *
     * @param id token identifier
     * @return JSON token record
     * @throws TrustClientException if the request fails
     */
    public String getToken(String id) throws TrustClientException {
        return processRequest(tokenPath("get"), id, APPLICATION_JSON);
    }
}
