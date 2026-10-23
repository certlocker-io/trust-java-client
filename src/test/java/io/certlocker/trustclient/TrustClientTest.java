package io.certlocker.trustclient;

import io.certlocker.trustclient.client.TrustClient;
import io.certlocker.trustclient.client.TrustClientBuilder;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author dhudson
 * 22/10/2026 - 13:03
 */
public class TrustClientTest {

    @Test
    public void buildsClientFromUrlApiKeyAndHttpSettings() {
        try (TrustClient client = new TrustClientBuilder()
                .url("https://trust.example.com/api")
                .apiKey("secret-key")
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .version(HttpClient.Version.HTTP_1_1)
                .proxy(HttpClient.Builder.NO_PROXY)
                .build()) {

            assertEquals(URI.create("https://trust.example.com/api"), client.getUrl());
            assertEquals("secret-key", client.getApiKey());
            assertEquals(Optional.of(Duration.ofSeconds(5)), client.getHttpClient().connectTimeout());
            assertEquals(HttpClient.Redirect.NORMAL, client.getHttpClient().followRedirects());
            assertEquals(HttpClient.Version.HTTP_1_1, client.getHttpClient().version());
            assertEquals(Optional.of(HttpClient.Builder.NO_PROXY), client.getHttpClient().proxy());
        }
    }

    @Test
    public void acceptsAnHttpClientBuilder() {
        try (TrustClient client = TrustClient.builder()
                .url(URI.create("http://localhost:8080"))
                .apiKey("key")
                .httpClientBuilder(HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .followRedirects(HttpClient.Redirect.ALWAYS))
                .build()) {

            assertEquals(URI.create("http://localhost:8080"), client.getUrl());
            assertEquals(Optional.of(Duration.ofSeconds(3)), client.getHttpClient().connectTimeout());
            assertEquals(HttpClient.Redirect.ALWAYS, client.getHttpClient().followRedirects());
        }
    }

    @Test
    public void defaultsConnectTimeoutWhenHttpClientIsNotCustomised() {
        try (TrustClient client = new TrustClientBuilder()
                .url("  https://trust.example.com  ")
                .apiKey("key")
                .build()) {

            assertEquals(URI.create("https://trust.example.com"), client.getUrl());
            assertEquals(Optional.of(TrustClientBuilder.DEFAULT_CONNECT_TIMEOUT), client.getHttpClient().connectTimeout());
        }
    }

    @Test
    public void suppliedHttpClientBuilderIsUsedAsGiven() {
        try (TrustClient client = new TrustClientBuilder()
                .url("https://trust.example.com")
                .apiKey("key")
                .httpClientBuilder(HttpClient.newBuilder())
                .build()) {

            assertEquals(Optional.empty(), client.getHttpClient().connectTimeout());
        }
    }

    @Test
    public void requiresUrlAndApiKey() {
        IllegalArgumentException missingUrl = assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().apiKey("key").build());
        assertEquals("url is required", missingUrl.getMessage());

        IllegalArgumentException missingKey = assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().url("https://trust.example.com").build());
        assertEquals("apiKey is required", missingKey.getMessage());
    }

    @Test
    public void rejectsBlankApiKeyAndInvalidUrl() {
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().apiKey("  "));
        assertThrows(NullPointerException.class,
                () -> new TrustClientBuilder().apiKey(null));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().url("ftp://files.example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().url("/relative"));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().url("https://"));
        assertThrows(NullPointerException.class,
                () -> new TrustClientBuilder().url((String) null));
    }

    @Test
    public void forwardsHttpClientBuilderValidation() {
        TrustClientBuilder builder = new TrustClientBuilder()
                .url("https://trust.example.com")
                .apiKey("key");

        assertThrows(IllegalArgumentException.class, () -> builder.priority(0));
    }

}
