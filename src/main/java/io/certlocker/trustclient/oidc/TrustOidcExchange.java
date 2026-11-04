package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.model.token.TokenType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.EdECPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Calls Gateway {@code POST /rest/api/v1/oidc/exchange}.
 * <p>
 * By default the matched principal's {@code defaultTokenType} is minted (typically
 * {@link TokenType#SECRET}). Pass an explicit {@link TokenType} to request
 * {@link TokenType#CERTIFICATE} or {@link TokenType#MCP} when the principal allows it.
 */
public final class TrustOidcExchange {

    private static final String PATH = "/rest/api/v1/oidc/exchange";
    /** Accept both released Gateway JSON naming conventions. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private TrustOidcExchange() {
    }

    /**
     * Exchanges an OIDC id token for a short-lived Trust token (principal default type).
     *
     * @param trustUrl Trust/Gateway base URL
     * @param idToken  signed OIDC JWT (GitHub Actions, DEVICE, or other supported issuer)
     * @return exchange result including {@code tokenId} and {@code accountId}
     * @throws TrustClientException if the request fails or the response is incomplete
     */
    public static OidcExchangeResult exchange(URI trustUrl, String idToken) throws TrustClientException {
        return exchange(trustUrl, idToken, null, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    /**
     * Exchanges an OIDC id token requesting an explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param idToken   signed OIDC JWT
     * @param tokenType requested {@link TokenType#SECRET}, {@link TokenType#CERTIFICATE}, or
     *                  {@link TokenType#MCP}; {@code null} uses the principal default
     * @return exchange result including {@code tokenId} and {@code accountId}
     * @throws TrustClientException if the request fails or the response is incomplete
     */
    public static OidcExchangeResult exchange(URI trustUrl, String idToken, TokenType tokenType)
            throws TrustClientException {
        return exchange(trustUrl, idToken, tokenType,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    /**
     * Exchanges an OIDC id token using the supplied HTTP client (principal default type).
     *
     * @param trustUrl   Trust/Gateway base URL
     * @param idToken    signed OIDC JWT
     * @param httpClient client used for the exchange POST
     * @return exchange result including {@code tokenId} and {@code accountId}
     * @throws TrustClientException if the request fails or the response is incomplete
     */
    public static OidcExchangeResult exchange(URI trustUrl, String idToken, HttpClient httpClient)
            throws TrustClientException {
        return exchange(trustUrl, idToken, null, httpClient);
    }

    /**
     * Exchanges an OIDC id token using the supplied HTTP client and optional mint type.
     *
     * @param trustUrl   Trust/Gateway base URL
     * @param idToken    signed OIDC JWT
     * @param tokenType  requested mint type, or {@code null} for principal default
     * @param httpClient client used for the exchange POST
     * @return exchange result including {@code tokenId} and {@code accountId}
     * @throws TrustClientException if the request fails or the response is incomplete
     */
    public static OidcExchangeResult exchange(URI trustUrl, String idToken, TokenType tokenType, HttpClient httpClient)
            throws TrustClientException {
        if (trustUrl == null) {
            throw new TrustClientException("trustUrl is required");
        }
        if (idToken == null || idToken.isBlank()) {
            throw new TrustClientException("idToken is required");
        }
        if (tokenType != null
                && tokenType != TokenType.SECRET
                && tokenType != TokenType.CERTIFICATE
                && tokenType != TokenType.MCP) {
            throw new TrustClientException(
                    "OIDC exchange tokenType must be SECRET, CERTIFICATE, or MCP (got " + tokenType + ")");
        }

        String body = buildRequestBody(idToken, tokenType);
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
            String error = textEither(root, "errorMessage", "error_message");
            if (error != null && !error.isBlank()) {
                throw new TrustClientException("OIDC exchange denied: " + error);
            }
            String tokenId = textEither(root, "tokenId", "token_id");
            if (tokenId == null || tokenId.isBlank()) {
                throw new TrustClientException("OIDC exchange response missing tokenId");
            }
            Instant expiresAt = parseExpires(textEither(root, "expiresAt", "expires_at"));
            return new OidcExchangeResult(
                    tokenId,
                    expiresAt,
                    textEither(root, "tokenType", "token_type"),
                    textEither(root, "accountId", "account_id"),
                    textEither(root, "principalId", "principal_id"));
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("OIDC exchange failed: " + e.getMessage(), e);
        }
    }

    /**
     * GitHub Actions ambient OIDC → Gateway exchange (principal default mint type).
     *
     * @param trustUrl Trust/Gateway base URL
     * @param audience per-account OIDC audience
     * @return exchange result
     * @throws TrustClientException if ambient OIDC is unavailable or exchange fails
     */
    public static OidcExchangeResult fromGitHubActions(URI trustUrl, String audience) throws TrustClientException {
        return fromGitHubActions(trustUrl, audience, null);
    }

    /**
     * GitHub Actions ambient OIDC → Gateway exchange with explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param audience  per-account OIDC audience
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if ambient OIDC is unavailable or exchange fails
     */
    public static OidcExchangeResult fromGitHubActions(URI trustUrl, String audience, TokenType tokenType)
            throws TrustClientException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        String idToken = GitHubActionsOidc.requestIdToken(audience, client);
        return exchange(trustUrl, idToken, tokenType, client);
    }

    /**
     * GCP ambient identity token (metadata server) → Gateway exchange.
     *
     * @param trustUrl Trust/Gateway base URL
     * @param audience per-account OIDC audience (must match Google ID token {@code aud})
     * @return exchange result
     * @throws TrustClientException if metadata identity or exchange fails
     */
    public static OidcExchangeResult fromGcp(URI trustUrl, String audience) throws TrustClientException {
        return fromGcp(trustUrl, audience, null);
    }

    /**
     * GCP ambient identity token → Gateway exchange with explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param audience  per-account OIDC audience
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if metadata identity or exchange fails
     */
    public static OidcExchangeResult fromGcp(URI trustUrl, String audience, TokenType tokenType)
            throws TrustClientException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        String idToken = GcpIdentityToken.requestIdToken(audience, client);
        return exchange(trustUrl, idToken, tokenType, client);
    }

    /**
     * Azure ambient managed-identity token (IMDS / App Service identity) → Gateway exchange.
     *
     * @param trustUrl Trust/Gateway base URL
     * @param audience per-account OIDC audience (passed as IMDS {@code resource})
     * @return exchange result
     * @throws TrustClientException if Azure identity or exchange fails
     */
    public static OidcExchangeResult fromAzure(URI trustUrl, String audience) throws TrustClientException {
        return fromAzure(trustUrl, audience, null);
    }

    /**
     * Azure ambient managed-identity token → Gateway exchange with explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param audience  per-account OIDC audience
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if Azure identity or exchange fails
     */
    public static OidcExchangeResult fromAzure(URI trustUrl, String audience, TokenType tokenType)
            throws TrustClientException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        String idToken = AzureIdentityToken.requestIdToken(audience, client);
        return exchange(trustUrl, idToken, tokenType, client);
    }

    /**
     * Azure DevOps Pipelines ambient OIDC ({@code SYSTEM_OIDCREQUESTURI}) → Gateway exchange.
     * Token audience is ADO's fixed {@code api://AzureADTokenExchange}; Trust matches
     * {@code AZURE_DEVOPS} principals by issuer org GUID + {@code sub}.
     *
     * @param trustUrl Trust/Gateway base URL
     * @return exchange result
     * @throws TrustClientException if Azure DevOps OIDC or exchange fails
     */
    public static OidcExchangeResult fromAzureDevOps(URI trustUrl) throws TrustClientException {
        return fromAzureDevOps(trustUrl, null);
    }

    /**
     * Azure DevOps Pipelines ambient OIDC → Gateway exchange with explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if Azure DevOps OIDC or exchange fails
     */
    public static OidcExchangeResult fromAzureDevOps(URI trustUrl, TokenType tokenType) throws TrustClientException {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        String idToken = AzureDevOpsOidc.requestIdToken(client);
        return exchange(trustUrl, idToken, tokenType, client);
    }

    /**
     * Explicit id token (DEVICE / workload JWT, or any pre-acquired OIDC JWT) → Gateway exchange.
     * Alias of {@link #exchange(URI, String)} for callers that want a clear non-ambient entry point.
     *
     * @param trustUrl Trust/Gateway base URL
     * @param idToken  signed OIDC JWT
     * @return exchange result
     * @throws TrustClientException if the exchange fails
     */
    public static OidcExchangeResult exchangeIdToken(URI trustUrl, String idToken) throws TrustClientException {
        return exchange(trustUrl, idToken);
    }

    /**
     * Explicit id token → Gateway exchange with explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param idToken   signed OIDC JWT
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if the exchange fails
     */
    public static OidcExchangeResult exchangeIdToken(URI trustUrl, String idToken, TokenType tokenType)
            throws TrustClientException {
        return exchange(trustUrl, idToken, tokenType);
    }

    /**
     * Mints a DEVICE Ed25519/{@code EdDSA} JWT and exchanges it for a Trust token
     * (principal default mint type).
     *
     * @param trustUrl Trust/Gateway base URL
     * @param config   DEVICE mint inputs (audience, deviceId, private key path or PEM)
     * @return exchange result
     * @throws TrustClientException if minting or exchange fails
     */
    public static OidcExchangeResult fromDeviceOidc(URI trustUrl, DeviceOidcConfig config)
            throws TrustClientException {
        return fromDeviceOidc(trustUrl, config, null);
    }

    /**
     * Mints a DEVICE Ed25519/{@code EdDSA} JWT and exchanges it requesting an explicit mint type.
     *
     * @param trustUrl  Trust/Gateway base URL
     * @param config    DEVICE mint inputs
     * @param tokenType requested mint type, or {@code null} for principal default
     * @return exchange result
     * @throws TrustClientException if minting or exchange fails
     */
    public static OidcExchangeResult fromDeviceOidc(URI trustUrl, DeviceOidcConfig config, TokenType tokenType)
            throws TrustClientException {
        if (config == null) {
            throw new TrustClientException("DeviceOidcConfig is required");
        }
        EdECPrivateKey key = config.getPrivateKeyPath() != null
                ? DeviceOidcPrivateKey.loadFromFile(config.getPrivateKeyPath())
                : DeviceOidcPrivateKey.loadFromPem(config.getPrivateKeyPem());
        String idToken = DeviceOidcJwt.mint(
                config.getIssuer(),
                config.getAudience(),
                config.getDeviceId(),
                key,
                config.getKeyId(),
                config.getTtlMinutes());
        return exchange(trustUrl, idToken, tokenType);
    }

    private static String buildRequestBody(String idToken, TokenType tokenType) {
        StringBuilder b = new StringBuilder(64 + idToken.length());
        b.append("{\"idToken\":").append(quote(idToken));
        b.append(",\"id_token\":").append(quote(idToken));
        if (tokenType != null) {
            b.append(",\"tokenType\":").append(quote(tokenType.name()));
            b.append(",\"token_type\":").append(quote(tokenType.name()));
        }
        b.append('}');
        return b.toString();
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

    private static String textEither(JsonNode root, String camel, String snake) {
        String value = text(root, snake);
        return value == null || value.isBlank() ? text(root, camel) : value;
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
