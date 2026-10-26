package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Calls Gateway {@code POST /rest/api/v1/oidc/exchange}.
 */
public final class TrustOidcExchange {

    private static final String PATH = "/rest/api/v1/oidc/exchange";
    /** Gateway JSON is camelCase (not the asset snake_case mapper). */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private TrustOidcExchange() {
    }

    public static OidcExchangeResult exchange(URI trustUrl, String idToken) throws TrustClientException {
        return exchange(trustUrl, idToken, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public static OidcExchangeResult exchange(URI trustUrl, String idToken, HttpClient httpClient)
            throws TrustClientException {
        if (trustUrl == null) {
            throw new TrustClientException("trustUrl is required");
        }
        if (idToken == null || idToken.isBlank()) {
            throw new TrustClientException("idToken is required");
        }

        String body = "{\"idToken\":" + quote(idToken) + "}";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(trimSlash(trustUrl.toString()) + PATH))
                .timeout(Duration.ofSeconds(30))
                .header("content-type", "application/json")
                .header("accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new TrustClientException("OIDC exchange failed: HTTP " + response.statusCode()
                        + " body=" + truncate(response.body()));
            }
            JsonNode root = JSON.readTree(response.body());
            if (root == null) {
                throw new TrustClientException("OIDC exchange returned empty body");
            }
            String error = text(root, "errorMessage");
            if (error != null && !error.isBlank()) {
                throw new TrustClientException("OIDC exchange denied: " + error);
            }
            String tokenId = text(root, "tokenId");
            if (tokenId == null || tokenId.isBlank()) {
                throw new TrustClientException("OIDC exchange response missing tokenId");
            }
            Instant expiresAt = parseExpires(text(root, "expiresAt"));
            return new OidcExchangeResult(
                    tokenId,
                    expiresAt,
                    text(root, "tokenType"),
                    text(root, "accountId"),
                    text(root, "principalId"));
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("OIDC exchange failed: " + e.getMessage(), e);
        }
    }

    /**
     * GitHub Actions ambient OIDC → Gateway exchange.
     */
    public static OidcExchangeResult fromGitHubActions(URI trustUrl, String audience) throws TrustClientException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        String idToken = GitHubActionsOidc.requestIdToken(audience, client);
        return exchange(trustUrl, idToken, client);
    }

    private static Instant parseExpires(String expiresAt) {
        if (expiresAt == null || expiresAt.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(expiresAt);
        } catch (Exception ignored) {
            try {
                return LocalDateTime.parse(expiresAt).toInstant(ZoneOffset.UTC);
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static String text(JsonNode root, String field) {
        JsonNode n = root.get(field);
        return n == null || n.isNull() ? null : n.asString();
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\', '"' -> {
                    b.append('\\');
                    b.append(c);
                }
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> b.append(c);
            }
        }
        b.append('"');
        return b.toString();
    }

    private static String trimSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > 300 ? s.substring(0, 300) + "…" : s;
    }
}
