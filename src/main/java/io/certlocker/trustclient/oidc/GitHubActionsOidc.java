package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * Obtains the ambient GitHub Actions OIDC JWT for a Trust per-account audience.
 * <p>
 * Requires workflow {@code permissions: id-token: write} and env
 * {@code ACTIONS_ID_TOKEN_REQUEST_URL} / {@code ACTIONS_ID_TOKEN_REQUEST_TOKEN}.
 */
public final class GitHubActionsOidc {

    public static final String REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL";
    public static final String REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

    private GitHubActionsOidc() {
    }

    /**
     * @return true when running under GitHub Actions with OIDC request env present
     */
    public static boolean isAvailable() {
        return nonBlank(System.getenv(REQUEST_URL_ENV)) && nonBlank(System.getenv(REQUEST_TOKEN_ENV));
    }

    /**
     * Fetches an ID token with the given audience (per-account Trust audience).
     *
     * @param audience e.g. {@code https://trust.certlocker.io/oidc/<accountId>}
     * @return raw JWT
     */
    public static String requestIdToken(String audience) throws TrustClientException {
        return requestIdToken(audience, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public static String requestIdToken(String audience, HttpClient httpClient) throws TrustClientException {
        if (!nonBlank(audience)) {
            throw new TrustClientException("OIDC audience is required");
        }
        String requestUrl = System.getenv(REQUEST_URL_ENV);
        String requestToken = System.getenv(REQUEST_TOKEN_ENV);
        if (!nonBlank(requestUrl) || !nonBlank(requestToken)) {
            throw new TrustClientException("GitHub Actions OIDC env not present ("
                    + REQUEST_URL_ENV + " / " + REQUEST_TOKEN_ENV + ")");
        }

        String url = requestUrl
                + (requestUrl.contains("?") ? "&" : "?")
                + "audience=" + URLEncoder.encode(audience.trim(), StandardCharsets.UTF_8);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + requestToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new TrustClientException("GitHub OIDC token request failed: HTTP " + response.statusCode()
                        + " body=" + truncate(response.body()));
            }
            Optional<String> jwt = extractJsonString(response.body(), "value");
            if (jwt.isEmpty() || jwt.get().isBlank()) {
                throw new TrustClientException("GitHub OIDC response missing value");
            }
            return jwt.get();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("GitHub OIDC token request failed: " + e.getMessage(), e);
        }
    }

    private static Optional<String> extractJsonString(String json, String field) {
        if (json == null) {
            return Optional.empty();
        }
        // Minimal parse — avoid requiring Jackson on this hot path for a single field.
        String key = "\"" + field + "\"";
        int i = json.indexOf(key);
        if (i < 0) {
            return Optional.empty();
        }
        int colon = json.indexOf(':', i + key.length());
        if (colon < 0) {
            return Optional.empty();
        }
        int startQuote = json.indexOf('"', colon + 1);
        if (startQuote < 0) {
            return Optional.empty();
        }
        int endQuote = json.indexOf('"', startQuote + 1);
        if (endQuote < 0) {
            return Optional.empty();
        }
        return Optional.of(json.substring(startQuote + 1, endQuote));
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
