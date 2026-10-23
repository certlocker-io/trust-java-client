package io.certlocker.trustclient.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.*;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Builds a {@link TrustClient} connected to Trust with a URL and an API key.
 * <p>
 * HTTP settings are the same values accepted by {@link HttpClient.Builder}, so
 * the connection and the HTTP client are configured in one chain. When no HTTP
 * settings are supplied, the client uses a connect timeout of
 * {@link #DEFAULT_CONNECT_TIMEOUT}.
 * <pre>{@code
 * TrustClient client = new TrustClientBuilder()
 *         .url("https://trust.example.com")
 *         .apiKey(apiKey)
 *         .connectTimeout(Duration.ofSeconds(10))
 *         .followRedirects(HttpClient.Redirect.NORMAL)
 *         .build();
 * }</pre>
 * An existing JDK builder can be passed in instead:
 * <pre>{@code
 * TrustClient client = new TrustClientBuilder()
 *         .url("https://trust.example.com")
 *         .apiKey(apiKey)
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
    private String theApiKey;
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
     * Sets the API key sent as the {@code x-api-token} header.
     *
     * @param apiKey non-blank API key
     * @return this builder
     * @throws IllegalArgumentException if {@code apiKey} is blank
     */
    public TrustClientBuilder apiKey(String apiKey) {
        Objects.requireNonNull(apiKey, "apiKey");
        if (apiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey must not be blank");
        }
        theApiKey = apiKey;
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
     * @return a client for the configured URL and API key
     * @throws IllegalArgumentException if the URL or API key has not been set
     */
    public TrustClient build() {
        if (theUrl == null) {
            throw new IllegalArgumentException("url is required");
        }
        if (theApiKey == null || theApiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey is required");
        }
        return new TrustClient(theUrl, theApiKey, theHttpClientBuilder.build());
    }
}
