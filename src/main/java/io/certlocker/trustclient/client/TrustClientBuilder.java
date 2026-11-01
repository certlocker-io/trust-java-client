package io.certlocker.trustclient.client;

import io.certlocker.trustclient.auth.AuthCodePrompt;
import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.oidc.DeviceOidcConfig;
import io.certlocker.trustclient.oidc.DeviceOidcJwt;
import io.certlocker.trustclient.oidc.DeviceOidcPrivateKey;
import io.certlocker.trustclient.oidc.AzureDevOpsOidc;
import io.certlocker.trustclient.oidc.AzureIdentityToken;
import io.certlocker.trustclient.oidc.GcpIdentityToken;
import io.certlocker.trustclient.oidc.GitHubActionsOidc;
import io.certlocker.trustclient.oidc.OidcExchangeResult;
import io.certlocker.trustclient.oidc.TrustOidcExchange;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.interfaces.EdECPrivateKey;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Builds a {@link TrustClient} connected to Trust with a URL and an API token.
 * <p>
 * HTTP settings are the same values accepted by {@link HttpClient.Builder}, so
 * the connection and the HTTP client are configured in one chain. When no HTTP
 * settings are supplied, the client uses a connect timeout of
 * {@link #DEFAULT_CONNECT_TIMEOUT}.
 * <pre>{@code
 * TrustClient client = new TrustClientBuilder()
 *         .url("https://trust.example.com")
 *         .accountId(accountId)
 *         .apiToken(apiToken)
 *         .connectTimeout(Duration.ofSeconds(10))
 *         .followRedirects(HttpClient.Redirect.NORMAL)
 *         .build();
 * }</pre>
 * An existing JDK builder can be passed in instead:
 * <pre>{@code
 * TrustClient client = new TrustClientBuilder()
 *         .url("https://trust.example.com")
 *         .accountId(accountId)
 *         .apiToken(apiToken)
 *         .httpClientBuilder(HttpClient.newBuilder()
 *                 .connectTimeout(Duration.ofSeconds(5)))
 *         .build();
 * }</pre>
 * {@link #httpClientBuilder(HttpClient.Builder)} replaces any HTTP settings
 * already applied. Call it before the other HTTP methods when combining both.
 *
 * @author dhudson
 * 22/10/2026 - 13:05
 */
public final class TrustClientBuilder {

    /**
     * Connect timeout used when the caller does not set one and does not supply an {@link HttpClient.Builder}.
     */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private URI theUrl;
    private String theApiToken;
    private String theAccountId;
    private String theOidcAudience;
    private boolean preferAmbientOidc;
    private AuthCodePrompt theAuthCodePrompt;
    private HttpClient.Builder theHttpClientBuilder = HttpClient.newBuilder()
            .connectTimeout(DEFAULT_CONNECT_TIMEOUT);

    /**
     * Creates a builder with the {@linkplain #DEFAULT_CONNECT_TIMEOUT default connect timeout}.
     */
    public TrustClientBuilder() {
    }

    private static URI requireHttpUri(URI url) {
        Objects.requireNonNull(url, "url");
        if (!url.isAbsolute() || url.getHost() == null || url.getHost().isEmpty()) {
            throw new IllegalArgumentException("url must be an absolute http or https URI");
        }
        String scheme = url.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("url must use http or https");
        }
        return url;
    }

    /**
     * Sets the Trust base URL.
     *
     * @param url absolute {@code http} or {@code https} URL; surrounding whitespace is ignored
     * @return this builder
     * @throws IllegalArgumentException if {@code url} is not an absolute http or https URI
     */
    public TrustClientBuilder url(String url) {
        Objects.requireNonNull(url, "url");
        return url(URI.create(url.trim()));
    }

    /**
     * Sets the Trust base URL.
     *
     * @param url absolute {@code http} or {@code https} URI
     * @return this builder
     * @throws IllegalArgumentException if {@code url} is not an absolute http or https URI
     */
    public TrustClientBuilder url(URI url) {
        theUrl = requireHttpUri(url);
        return this;
    }

    /**
     * Sets the API token sent as the {@code x-api-token} header.
     *
     * @param apiToken non-blank API token
     * @return this builder
     * @throws IllegalArgumentException if {@code apiToken} is blank
     */
    public TrustClientBuilder apiToken(String apiToken) {
        Objects.requireNonNull(apiToken, "apiToken");
        if (apiToken.isBlank()) {
            throw new IllegalArgumentException("apiToken must not be blank");
        }
        theApiToken = apiToken;
        return this;
    }

    /**
     * Tenant account id for Gateway paths ({@code /v1/{resource}/{accountId}/…}).
     * Must match the API token's account.
     *
     * @param accountId non-blank account id
     * @return this builder
     * @throws IllegalArgumentException if {@code accountId} is blank
     */
    public TrustClientBuilder accountId(String accountId) {
        Objects.requireNonNull(accountId, "accountId");
        if (accountId.isBlank()) {
            throw new IllegalArgumentException("accountId must not be blank");
        }
        theAccountId = accountId;
        return this;
    }

    /**
     * Per-account OIDC audience, e.g. {@code https://trust.certlocker.io/oidc/<accountId>}.
     * Used by {@link #fromAmbientOidc(String, String)} and {@link #preferAmbientOidc(boolean)}.
     *
     * @param audience non-blank per-account audience URL
     * @return this builder
     */
    public TrustClientBuilder oidcAudience(String audience) {
        Objects.requireNonNull(audience, "audience");
        if (audience.isBlank()) {
            throw new IllegalArgumentException("oidcAudience must not be blank");
        }
        theOidcAudience = audience;
        return this;
    }

    /**
     * When true, {@link #build()} exchanges ambient GitHub Actions, GCP, Azure, or Azure DevOps OIDC
     * before using a break-glass apiToken.
     *
     * @param prefer {@code true} to prefer ambient OIDC exchange
     * @return this builder
     */
    public TrustClientBuilder preferAmbientOidc(boolean prefer) {
        preferAmbientOidc = prefer;
        return this;
    }

    /**
     * Convenience: URL + per-account audience; resolves credential via ambient GitHub, GCP, Azure,
     * or Azure DevOps OIDC exchange.
     * {@code accountId} is taken from the exchange response (must match the audience tenant).
     *
     * @param trustUrl Trust/Gateway base URL
     * @param audience per-account OIDC audience
     * @return client authenticated with the exchanged SECRET token
     * @throws TrustClientException if ambient OIDC exchange fails (wrapped as {@link IllegalStateException} from {@link #build()})
     */
    public static TrustClient fromAmbientOidc(String trustUrl, String audience) throws TrustClientException {
        return new TrustClientBuilder()
                .url(trustUrl)
                .oidcAudience(audience)
                .preferAmbientOidc(true)
                .build();
    }

    /**
     * Explicit OIDC JWT → Gateway exchange → {@link TrustClient}.
     * <p>
     * Use for DEVICE / workload JWTs (or any already-acquired id token). Does not read ambient
     * GitHub Actions env — pass the JWT from enrollment / dogfood mint / agent.
     *
     * @param trustUrl Trust/Gateway base URL (e.g. {@code http://localhost:8080/gateway})
     * @param idToken  signed OIDC JWT ({@code iss}/{@code aud}/{@code device_id} as required by Trust)
     * @return client authenticated with the exchanged SECRET token
     * @throws TrustClientException if exchange fails or {@code accountId} is missing from the response
     */
    public static TrustClient fromIdToken(String trustUrl, String idToken) throws TrustClientException {
        Objects.requireNonNull(trustUrl, "trustUrl");
        Objects.requireNonNull(idToken, "idToken");
        if (trustUrl.isBlank()) {
            throw new IllegalArgumentException("trustUrl must not be blank");
        }
        if (idToken.isBlank()) {
            throw new IllegalArgumentException("idToken must not be blank");
        }
        URI url = URI.create(trustUrl.trim());
        OidcExchangeResult exchanged = TrustOidcExchange.exchange(url, idToken);
        if (exchanged.accountId() == null || exchanged.accountId().isBlank()) {
            throw new TrustClientException("OIDC exchange response missing accountId");
        }
        return new TrustClientBuilder()
                .url(url)
                .apiToken(exchanged.tokenId())
                .accountId(exchanged.accountId())
                .build();
    }

    /**
     * DEVICE OIDC: mint Ed25519/{@code EdDSA} JWT from enrolled private key → Gateway exchange →
     * {@link TrustClient} with a short-lived {@code TokenType.SECRET}.
     * <p>
     * Private key stays on the machine (path or PEM string). Does not disturb
     * static {@link #apiToken(String)} paths.
     *
     * @param trustUrl Trust/Gateway base URL
     * @param config   audience, deviceId, private key path or PEM, optional keyId / ttl
     * @return client authenticated with the exchanged SECRET token
     * @throws TrustClientException if minting or exchange fails
     */
    public static TrustClient fromDeviceOidc(String trustUrl, DeviceOidcConfig config)
            throws TrustClientException {
        Objects.requireNonNull(trustUrl, "trustUrl");
        Objects.requireNonNull(config, "config");
        if (trustUrl.isBlank()) {
            throw new IllegalArgumentException("trustUrl must not be blank");
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
        return fromIdToken(trustUrl, idToken);
    }

    /**
     * DEVICE OIDC convenience: private key file path + required enrollment fields.
     *
     * @param trustUrl       Trust/Gateway base URL
     * @param audience       per-account aud (e.g. {@code https://trust.certlocker.io/oidc/<accountId>})
     * @param deviceId       enrolled {@code device_id}
     * @param privateKeyPath PKCS#8 PEM path from ui-edge enroll download
     * @param keyId          optional JWT {@code kid} (must match enrolled keyId when principal has one)
     * @return client authenticated with the exchanged SECRET token
     * @throws TrustClientException if minting or exchange fails
     */
    public static TrustClient fromDeviceOidc(
            String trustUrl,
            String audience,
            String deviceId,
            Path privateKeyPath,
            String keyId) throws TrustClientException {
        return fromDeviceOidc(trustUrl, DeviceOidcConfig.builder()
                .audience(audience)
                .deviceId(deviceId)
                .privateKeyPath(privateKeyPath)
                .keyId(keyId)
                .build());
    }

    /**
     * Prompt used when Gateway requires 2FA / accessCode on a user-bound token.
     *
     * @param prompt interactive prompt implementation
     * @return this builder
     */
    public TrustClientBuilder authCodePrompt(AuthCodePrompt prompt) {
        theAuthCodePrompt = prompt;
        return this;
    }

    /**
     * Uses this JDK builder for the HTTP client, in place of the one held so far.
     * <p>
     * Call this before the other HTTP methods when combining both. Those methods then apply to the supplied builder.
     *
     * @param httpClientBuilder JDK HTTP client builder
     * @return this builder
     */
    public TrustClientBuilder httpClientBuilder(HttpClient.Builder httpClientBuilder) {
        theHttpClientBuilder = Objects.requireNonNull(httpClientBuilder, "httpClientBuilder");
        return this;
    }

    /**
     * Sets the cookie handler used by the HTTP client.
     *
     * @param cookieHandler cookie handler for the HTTP client
     * @return this builder
     * @see HttpClient.Builder#cookieHandler(CookieHandler)
     */
    public TrustClientBuilder cookieHandler(CookieHandler cookieHandler) {
        theHttpClientBuilder.cookieHandler(cookieHandler);
        return this;
    }

    /**
     * Sets the HTTP connect timeout.
     * <p>
     * When this is not called and no JDK builder is supplied, the timeout is {@link #DEFAULT_CONNECT_TIMEOUT}.
     *
     * @param connectTimeout connect timeout
     * @return this builder
     * @see HttpClient.Builder#connectTimeout(Duration)
     */
    public TrustClientBuilder connectTimeout(Duration connectTimeout) {
        theHttpClientBuilder.connectTimeout(connectTimeout);
        return this;
    }

    /**
     * Sets the SSL context used by the HTTP client.
     *
     * @param sslContext SSL context
     * @return this builder
     * @see HttpClient.Builder#sslContext(SSLContext)
     */
    public TrustClientBuilder sslContext(SSLContext sslContext) {
        theHttpClientBuilder.sslContext(sslContext);
        return this;
    }

    /**
     * Sets the SSL parameters used by the HTTP client.
     *
     * @param sslParameters SSL parameters
     * @return this builder
     * @see HttpClient.Builder#sslParameters(SSLParameters)
     */
    public TrustClientBuilder sslParameters(SSLParameters sslParameters) {
        theHttpClientBuilder.sslParameters(sslParameters);
        return this;
    }

    /**
     * Sets the executor used for asynchronous HTTP requests.
     *
     * @param executor request executor
     * @return this builder
     * @see HttpClient.Builder#executor(Executor)
     */
    public TrustClientBuilder executor(Executor executor) {
        theHttpClientBuilder.executor(executor);
        return this;
    }

    /**
     * Sets the redirect policy used by the HTTP client.
     *
     * @param followRedirects redirect policy
     * @return this builder
     * @see HttpClient.Builder#followRedirects(HttpClient.Redirect)
     */
    public TrustClientBuilder followRedirects(HttpClient.Redirect followRedirects) {
        theHttpClientBuilder.followRedirects(followRedirects);
        return this;
    }

    /**
     * Sets the preferred HTTP protocol version.
     *
     * @param version preferred HTTP version
     * @return this builder
     * @see HttpClient.Builder#version(HttpClient.Version)
     */
    public TrustClientBuilder version(HttpClient.Version version) {
        theHttpClientBuilder.version(version);
        return this;
    }

    /**
     * Sets the HTTP/2 priority for requests, from 1 to 256.
     *
     * @param priority request priority
     * @return this builder
     * @throws IllegalArgumentException if {@code priority} is outside 1 to 256
     * @see HttpClient.Builder#priority(int)
     */
    public TrustClientBuilder priority(int priority) {
        theHttpClientBuilder.priority(priority);
        return this;
    }

    /**
     * Sets the proxy selector used by the HTTP client.
     *
     * @param proxy proxy selector, or {@link HttpClient.Builder#NO_PROXY} to disable proxies
     * @return this builder
     * @see HttpClient.Builder#proxy(ProxySelector)
     */
    public TrustClientBuilder proxy(ProxySelector proxy) {
        theHttpClientBuilder.proxy(proxy);
        return this;
    }

    /**
     * Sets the authenticator used by the HTTP client.
     *
     * @param authenticator authenticator for requests that require authentication
     * @return this builder
     * @see HttpClient.Builder#authenticator(Authenticator)
     */
    public TrustClientBuilder authenticator(Authenticator authenticator) {
        theHttpClientBuilder.authenticator(authenticator);
        return this;
    }

    /**
     * Sets the local address the HTTP client binds to.
     *
     * @param localAddress local address to bind, or {@code null} for any local address
     * @return this builder
     * @see HttpClient.Builder#localAddress(InetAddress)
     */
    public TrustClientBuilder localAddress(InetAddress localAddress) {
        theHttpClientBuilder.localAddress(localAddress);
        return this;
    }

    /**
     * Builds the client.
     *
     * @return a client for the configured URL, account, and API token
     * @throws IllegalArgumentException if the URL, account id, or API token has not been set
     */
    public TrustClient build() {
        if (theUrl == null) {
            throw new IllegalArgumentException("url is required");
        }
        HttpClient httpClient = theHttpClientBuilder.build();
        String apiToken = theApiToken;
        String accountId = theAccountId;
        if ((apiToken == null || apiToken.isBlank()) || preferAmbientOidc) {
            boolean ambientGha = GitHubActionsOidc.isAvailable();
            boolean ambientGcp = !ambientGha && GcpIdentityToken.isAvailable();
            boolean ambientAzure = !ambientGha && !ambientGcp && AzureIdentityToken.isAvailable();
            boolean ambientAzureDevOps = !ambientGha && !ambientGcp && !ambientAzure
                    && AzureDevOpsOidc.isAvailable();
            if (preferAmbientOidc || ambientGha || ambientGcp || ambientAzure || ambientAzureDevOps) {
                try {
                    OidcExchangeResult exchanged;
                    if (ambientGha) {
                        requireOidcAudience("GitHub Actions");
                        exchanged = TrustOidcExchange.fromGitHubActions(theUrl, theOidcAudience);
                    } else if (ambientGcp) {
                        requireOidcAudience("GCP");
                        exchanged = TrustOidcExchange.fromGcp(theUrl, theOidcAudience);
                    } else if (ambientAzure) {
                        requireOidcAudience("Azure");
                        exchanged = TrustOidcExchange.fromAzure(theUrl, theOidcAudience);
                    } else if (ambientAzureDevOps) {
                        // ADO tokens use fixed aud api://AzureADTokenExchange — no Trust audience.
                        exchanged = TrustOidcExchange.fromAzureDevOps(theUrl);
                    } else if (preferAmbientOidc && AzureDevOpsOidc.isAvailable()) {
                        exchanged = TrustOidcExchange.fromAzureDevOps(theUrl);
                    } else {
                        throw new TrustClientException(
                                "No ambient OIDC provider available (GitHub Actions, GCP, Azure, or Azure DevOps)");
                    }
                    apiToken = exchanged.tokenId();
                    if (accountId == null || accountId.isBlank()) {
                        accountId = exchanged.accountId();
                    }
                } catch (TrustClientException e) {
                    if (apiToken == null || apiToken.isBlank()) {
                        throw new IllegalStateException("Ambient OIDC exchange failed and no apiToken set", e);
                    }
                    // Break-glass apiToken remains when exchange fails and apiToken was provided.
                }
            }
        }
        if (apiToken == null || apiToken.isBlank()) {
            throw new IllegalArgumentException(
                    "apiToken is required (or enable ambient OIDC with oidcAudience / preferAmbientOidc)");
        }
        if (accountId == null || accountId.isBlank()) {
            throw new IllegalArgumentException("accountId is required");
        }
        return new TrustClient(theUrl, apiToken, accountId, httpClient, theAuthCodePrompt);
    }

    private void requireOidcAudience(String providerLabel) throws TrustClientException {
        if (theOidcAudience == null || theOidcAudience.isBlank()) {
            throw new TrustClientException("oidcAudience is required for " + providerLabel + " OIDC");
        }
    }
}
