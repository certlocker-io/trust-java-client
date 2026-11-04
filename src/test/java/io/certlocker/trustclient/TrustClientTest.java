package io.certlocker.trustclient;

import com.sun.net.httpserver.HttpServer;
import io.certlocker.trustclient.client.TrustClient;
import io.certlocker.trustclient.client.TrustClientBuilder;
import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.model.secret.*;
import io.certlocker.trustclient.service.TrustService;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author dhudson
 * 22/10/2026 - 13:03
 */
public class TrustClientTest {

    @Test
    public void buildsClientFromUrlApiTokenAndHttpSettings() {
        try (TrustClient client = new TrustClientBuilder()
                .url("https://trust.example.com/api")
                .accountId("acct-1")
                .apiToken("secret-key")
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .version(HttpClient.Version.HTTP_1_1)
                .proxy(HttpClient.Builder.NO_PROXY)
                .build()) {

            assertEquals(URI.create("https://trust.example.com/api"), client.getUrl());
            assertEquals("secret-key", client.getApiToken());
            assertEquals("acct-1", client.getAccountId());
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
                .accountId("acct-1")
                .apiToken("key")
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
                .accountId("acct-1")
                .apiToken("key")
                .build()) {

            assertEquals(URI.create("https://trust.example.com"), client.getUrl());
            assertEquals(Optional.of(TrustClientBuilder.DEFAULT_CONNECT_TIMEOUT), client.getHttpClient().connectTimeout());
        }
    }

    @Test
    public void suppliedHttpClientBuilderIsUsedAsGiven() {
        try (TrustClient client = new TrustClientBuilder()
                .url("https://trust.example.com")
                .accountId("acct-1")
                .apiToken("key")
                .httpClientBuilder(HttpClient.newBuilder())
                .build()) {

            assertEquals(Optional.empty(), client.getHttpClient().connectTimeout());
        }
    }

    @Test
    public void requiresUrlApiTokenAndAccountId() {
        IllegalArgumentException missingUrl = assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().accountId("acct-1").apiToken("key").build());
        assertEquals("url is required", missingUrl.getMessage());

        RuntimeException missingKey = assertThrows(RuntimeException.class,
                () -> new TrustClientBuilder().url("https://trust.example.com").accountId("acct-1").build());
        if (missingKey instanceof IllegalArgumentException) {
            assertTrue(missingKey.getMessage().startsWith("apiToken is required"));
        } else {
            assertInstanceOf(IllegalStateException.class, missingKey);
            assertEquals("Ambient OIDC exchange failed and no apiToken set", missingKey.getMessage());
            assertNotNull(missingKey.getCause());
        }

        IllegalArgumentException missingAccount = assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().url("https://trust.example.com").apiToken("key").build());
        assertEquals("accountId is required", missingAccount.getMessage());
    }

    @Test
    public void rejectsBlankApiTokenAndInvalidUrl() {
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().apiToken("  "));
        assertThrows(NullPointerException.class,
                () -> new TrustClientBuilder().apiToken(null));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustClientBuilder().accountId("  "));
        assertThrows(NullPointerException.class,
                () -> new TrustClientBuilder().accountId(null));
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
                .accountId("acct-1")
                .apiToken("key");

        assertThrows(IllegalArgumentException.class, () -> builder.priority(0));
    }

    /**
     * Exercises request → Gateway needsInput (401 + {@code x-access-response} + prompt body) →
     * prompt shows server text → retry with {@code x-access-code} → success.
     */
    @Test
    public void twoFATest() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        AtomicReference<String> receivedAccessCode = new AtomicReference<>();
        AtomicReference<String> promptedText = new AtomicReference<>();
        String serverPrompt = "Please enter verification code emailed to you";

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/gateway/rest/api/v1/secret/acct-test/fetch", exchange -> {
            int n = hits.incrementAndGet();
            String accessCode = exchange.getRequestHeaders().getFirst(TrustClient.ACCESS_CODE_HEADER);
            receivedAccessCode.set(accessCode);
            if (n == 1) {
                byte[] body = serverPrompt.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add(TrustClient.ACCESS_RESPONSE_HEADER, "EMAIL");
                exchange.getResponseHeaders().add("Content-Type", "text/plain");
                exchange.sendResponseHeaders(TrustClient.ACCESS_REQUIRED_STATUS, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
                return;
            }
            if (!"email-code-99".equals(accessCode)) {
                byte[] body = "Invalid email verification code".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain");
                exchange.sendResponseHeaders(400, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
                return;
            }
            byte[] body = "super-secret-value".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();

        try (TrustService service = new TrustService(TrustClient.builder()
                .apiToken("test-token")
                .accountId("acct-test")
                .url("http://127.0.0.1:" + server.getAddress().getPort() + "/gateway")
                .authCodePrompt(prompt -> {
                    promptedText.set(prompt);
                    return "email-code-99";
                }))) {

            String contents = service.fetchSecret();
            assertEquals("super-secret-value", contents);
            assertEquals(2, hits.get());
            assertEquals("email-code-99", receivedAccessCode.get());
            assertEquals(serverPrompt, promptedText.get());
            assertEquals(401, TrustClient.ACCESS_REQUIRED_STATUS);
        } finally {
            server.stop(0);
        }
    }

}
