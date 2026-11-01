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

/**
 * Obtains the ambient Azure DevOps Pipelines OIDC JWT via {@code SYSTEM_OIDCREQUESTURI}.
 * <p>
 * Requires pipeline env {@link #OIDC_REQUEST_URI_ENV} and a bearer
 * {@link #ACCESS_TOKEN_ENV} (map {@code System.AccessToken} into the job).
 * Optional {@link #SERVICE_CONNECTION_ID_ENV} scopes the token to a service connection
 * ({@code sub=sc://…}); without it ADO may return a pipeline-scoped subject ({@code p://…}).
 * <p>
 * ADO OIDC tokens use fixed audience {@code api://AzureADTokenExchange} — Trust principals
 * bind on {@code sub} (and issuer org GUID), not the Trust per-account audience URL.
 */
public final class AzureDevOpsOidc {

    /** Azure Pipelines variable {@code System.OidcRequestUri}. */
    public static final String OIDC_REQUEST_URI_ENV = "SYSTEM_OIDCREQUESTURI";

    /**
     * Bearer for the OIDC request. Map {@code env: SYSTEM_ACCESSTOKEN: $(System.AccessToken)}
     * (and {@code persistCredentials} / job permissions as needed).
     */
    public static final String ACCESS_TOKEN_ENV = "SYSTEM_ACCESSTOKEN";

    /**
     * Optional service connection id. AzureCLI@2 / AzurePowerShell@5 expose
     * {@code AZURESUBSCRIPTION_SERVICE_CONNECTION_ID} when a subscription is selected.
     */
    public static final String SERVICE_CONNECTION_ID_ENV = "AZURESUBSCRIPTION_SERVICE_CONNECTION_ID";

    /** Alternate explicit service-connection id env for non-AzureRM tasks. */
    public static final String SERVICE_CONNECTION_ID_ALT_ENV = "SYSTEM_OIDC_SERVICE_CONNECTION_ID";

    private static final String API_VERSION = "7.1";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private AzureDevOpsOidc() {
    }

    /**
     * Returns whether ambient Azure DevOps OIDC request env is present.
     *
     * @return {@code true} when {@link #OIDC_REQUEST_URI_ENV} and {@link #ACCESS_TOKEN_ENV} are set
     */
    public static boolean isAvailable() {
        return nonBlank(System.getenv(OIDC_REQUEST_URI_ENV)) && nonBlank(System.getenv(ACCESS_TOKEN_ENV));
    }

    /**
     * Fetches an Azure DevOps OIDC id token (fixed aud {@code api://AzureADTokenExchange}).
     *
     * @return raw JWT ({@code oidcToken} from the OIDC create response)
     * @throws TrustClientException if env is missing, the request fails, or the response has no token
     */
    public static String requestIdToken() throws TrustClientException {
        return requestIdToken(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    /**
     * Fetches an Azure DevOps OIDC id token using the supplied HTTP client.
     *
     * @param httpClient client used for the OIDC request
     * @return raw JWT
     * @throws TrustClientException if env is missing, the request fails, or the response has no token
     */
    public static String requestIdToken(HttpClient httpClient) throws TrustClientException {
        String requestUri = System.getenv(OIDC_REQUEST_URI_ENV);
        String accessToken = System.getenv(ACCESS_TOKEN_ENV);
        if (!nonBlank(requestUri) || !nonBlank(accessToken)) {
            throw new TrustClientException("Azure DevOps OIDC env not present ("
                    + OIDC_REQUEST_URI_ENV + " / " + ACCESS_TOKEN_ENV + ")");
        }

        String serviceConnectionId = firstNonBlank(
                System.getenv(SERVICE_CONNECTION_ID_ENV),
                System.getenv(SERVICE_CONNECTION_ID_ALT_ENV));

        String url = requestUri
                + (requestUri.contains("?") ? "&" : "?")
                + "api-version=" + URLEncoder.encode(API_VERSION, StandardCharsets.UTF_8);
        if (nonBlank(serviceConnectionId)) {
            url += "&serviceConnectionId=" + URLEncoder.encode(serviceConnectionId.trim(), StandardCharsets.UTF_8);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new TrustClientException("Azure DevOps OIDC token request failed: HTTP "
                        + response.statusCode() + " body=" + truncate(response.body()));
            }
            JsonNode root = JSON.readTree(response.body());
            if (root == null) {
                throw new TrustClientException("Azure DevOps OIDC response empty");
            }
            String token = text(root, "oidcToken");
            if (!nonBlank(token)) {
                // Some samples nest under a different key; accept "token" as fallback.
                token = text(root, "token");
            }
            if (!nonBlank(token)) {
                throw new TrustClientException("Azure DevOps OIDC response missing oidcToken");
            }
            return token;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("Azure DevOps OIDC token request failed: " + e.getMessage(), e);
        }
    }

    private static String text(JsonNode root, String field) {
        JsonNode n = root.get(field);
        return n == null || n.isNull() ? null : n.asString();
    }

    private static String firstNonBlank(String a, String b) {
        if (nonBlank(a)) {
            return a;
        }
        return nonBlank(b) ? b : null;
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
