package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Obtains an Entra / Azure managed-identity access token for a Trust per-account audience.
 * <p>
 * Tries App Service / Functions {@code IDENTITY_ENDPOINT} + {@code IDENTITY_HEADER} first,
 * then IMDS {@code http://169.254.169.254/metadata/identity/oauth2/token} with header
 * {@code Metadata: true} and query {@code resource=} (audience).
 */
public final class AzureIdentityToken {

    /** Default Azure Instance Metadata Service endpoint. */
    public static final String DEFAULT_IMDS_BASE = "http://169.254.169.254";

    /** App Service / Functions / Arc identity endpoint. */
    public static final String IDENTITY_ENDPOINT_ENV = "IDENTITY_ENDPOINT";

    /** Header secret paired with {@link #IDENTITY_ENDPOINT_ENV}. */
    public static final String IDENTITY_HEADER_ENV = "IDENTITY_HEADER";

    /** Optional client id when multiple user-assigned identities are present. */
    public static final String AZURE_CLIENT_ID_ENV = "AZURE_CLIENT_ID";

    private static final String IMDS_TOKEN_PATH = "/metadata/identity/oauth2/token";
    private static final String IMDS_API_VERSION = "2018-02-01";
    private static final String APP_SERVICE_API_VERSION = "2019-08-01";

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final AtomicReference<Boolean> availableCache = new AtomicReference<>();

    private AzureIdentityToken() {
    }

    /**
     * Returns whether this process appears to have Azure managed-identity ambient credentials.
     *
     * @return {@code true} when IDENTITY_ENDPOINT is set or IMDS responds to a short probe
     */
    public static boolean isAvailable() {
        if (nonBlank(System.getenv(IDENTITY_ENDPOINT_ENV))
                && nonBlank(System.getenv(IDENTITY_HEADER_ENV))) {
            return true;
        }
        Boolean cached = availableCache.get();
        if (cached != null) {
            return cached;
        }
        boolean ok = probeImds();
        availableCache.compareAndSet(null, ok);
        return ok;
    }

    /**
     * Fetches an Entra access token with {@code resource} / audience set to the Trust audience.
     *
     * @param audience e.g. {@code https://trust.certlocker.io/oidc/<accountId>}
     * @return raw JWT ({@code access_token} from the identity endpoint)
     * @throws TrustClientException if the identity request fails or returns empty
     */
    public static String requestIdToken(String audience) throws TrustClientException {
        return requestIdToken(audience, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build());
    }

    /**
     * Fetches an Entra access token using the supplied HTTP client.
     *
     * @param audience   Trust per-account audience ({@code resource} query param)
     * @param httpClient client used for the identity request
     * @return raw JWT
     * @throws TrustClientException if the identity request fails or returns empty
     */
    public static String requestIdToken(String audience, HttpClient httpClient) throws TrustClientException {
        if (!nonBlank(audience)) {
            throw new TrustClientException("OIDC audience is required");
        }
        String endpoint = System.getenv(IDENTITY_ENDPOINT_ENV);
        String header = System.getenv(IDENTITY_HEADER_ENV);
        if (nonBlank(endpoint) && nonBlank(header)) {
            return requestFromAppService(audience.trim(), endpoint.trim(), header.trim(), httpClient);
        }
        return requestFromImds(audience.trim(), httpClient);
    }

    private static String requestFromAppService(
            String audience, String endpoint, String identityHeader, HttpClient httpClient)
            throws TrustClientException {
        String url = appendQuery(endpoint,
                "api-version=" + APP_SERVICE_API_VERSION
                        + "&resource=" + URLEncoder.encode(audience, StandardCharsets.UTF_8)
                        + clientIdQuery());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("X-IDENTITY-HEADER", identityHeader)
                .GET()
                .build();
        return sendAndExtractAccessToken(httpClient, request, "Azure App Service identity");
    }

    private static String requestFromImds(String audience, HttpClient httpClient) throws TrustClientException {
        String url = DEFAULT_IMDS_BASE + IMDS_TOKEN_PATH
                + "?api-version=" + IMDS_API_VERSION
                + "&resource=" + URLEncoder.encode(audience, StandardCharsets.UTF_8)
                + clientIdQuery();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Metadata", "true")
                .GET()
                .build();
        return sendAndExtractAccessToken(httpClient, request, "Azure IMDS identity");
    }

    private static String sendAndExtractAccessToken(HttpClient httpClient, HttpRequest request, String label)
            throws TrustClientException {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new TrustClientException(label + " token request failed: HTTP " + response.statusCode()
                        + " body=" + truncate(response.body()));
            }
            JsonNode root = JSON.readTree(response.body());
            if (root == null) {
                throw new TrustClientException(label + " token response empty");
            }
            JsonNode tokenNode = root.get("access_token");
            String jwt = tokenNode == null || tokenNode.isNull() ? null : tokenNode.asString();
            if (jwt == null || jwt.isBlank()) {
                throw new TrustClientException(label + " response missing access_token");
            }
            return jwt.trim();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException(label + " token request failed: " + e.getMessage(), e);
        }
    }

    private static boolean probeImds() {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
            String url = DEFAULT_IMDS_BASE + "/metadata/instance?api-version=" + IMDS_API_VERSION;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(400))
                    .header("Metadata", "true")
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static String clientIdQuery() {
        String clientId = System.getenv(AZURE_CLIENT_ID_ENV);
        if (!nonBlank(clientId)) {
            return "";
        }
        return "&client_id=" + URLEncoder.encode(clientId.trim(), StandardCharsets.UTF_8);
    }

    private static String appendQuery(String endpoint, String query) {
        if (endpoint.contains("?")) {
            return endpoint + "&" + query;
        }
        return endpoint + "?" + query;
    }

    private static boolean nonBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }
}
