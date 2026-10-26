package io.certlocker.trustclient.auth;

import io.certlocker.trustclient.exception.TrustClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpServer;

/**
 * Short-lived loopback HTTP listener for Trust CLI localhost-redirect login (Google / gcloud style).
 * <p>
 * Starts only for the duration of login, then shuts down. Device-code is a documented fallback
 * returned by {@code /auth/cli/start} but not the Phase 1 default path.
 */
public final class LocalhostLogin {

    private static final String START_PATH = "/rest/api/v1/auth/cli/start";
    private static final String COMPLETE_PATH = "/rest/api/v1/auth/cli/complete";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private LocalhostLogin() {
    }

    /**
     * Result of interactive login once Edge browser flow is wired.
     */
    public record Result(String tokenId, String userId, String accountId) {
    }

    /**
     * Starts loopback listener, opens browser to Trust CLI login, waits for callback, completes exchange.
     *
     * @param trustUrl Trust base URL
     * @param timeout  max wait for browser callback
     */
    public static Result login(URI trustUrl, Duration timeout) throws TrustClientException {
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        HttpServer server = null;
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            int port = server.getAddress().getPort();
            String redirectUri = "http://127.0.0.1:" + port + "/callback";

            CompletableFuture<Callback> callbackFuture = new CompletableFuture<>();
            server.createContext("/callback", exchange -> {
                try {
                    String query = exchange.getRequestURI().getRawQuery();
                    Callback cb = Callback.fromQuery(query);
                    byte[] ok = "<html><body>Trust login complete. You can close this window.</body></html>"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                    exchange.sendResponseHeaders(200, ok.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(ok);
                    }
                    callbackFuture.complete(cb);
                } catch (Exception e) {
                    callbackFuture.completeExceptionally(e);
                    byte[] err = ("Login callback error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                }
            });
            server.start();

            String startBody = "{\"redirectUri\":" + jsonQuote(redirectUri) + "}";
            HttpRequest startReq = HttpRequest.newBuilder()
                    .uri(URI.create(trimSlash(trustUrl.toString()) + START_PATH))
                    .timeout(Duration.ofSeconds(30))
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(startBody))
                    .build();
            HttpResponse<String> startRes = httpClient.send(startReq, HttpResponse.BodyHandlers.ofString());
            if (startRes.statusCode() != 200) {
                throw new TrustClientException("CLI login start failed: HTTP " + startRes.statusCode());
            }
            JsonNode start = JSON.readTree(startRes.body());
            String error = text(start, "errorMessage");
            if (error != null && !error.isBlank()) {
                throw new TrustClientException("CLI login start denied: " + error);
            }
            String authorizationUrl = text(start, "authorizationUrl");
            String state = text(start, "state");
            if (authorizationUrl == null || state == null) {
                throw new TrustClientException("CLI login start missing authorizationUrl/state");
            }

            openBrowser(authorizationUrl);

            Callback callback = callbackFuture.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (callback.state() != null && !callback.state().equals(state)) {
                throw new TrustClientException("CLI login state mismatch");
            }

            String completeBody = "{\"state\":" + jsonQuote(state)
                    + ",\"code\":" + jsonQuote(callback.code() == null ? "" : callback.code()) + "}";
            HttpRequest completeReq = HttpRequest.newBuilder()
                    .uri(URI.create(trimSlash(trustUrl.toString()) + COMPLETE_PATH))
                    .timeout(Duration.ofSeconds(30))
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(completeBody))
                    .build();
            HttpResponse<String> completeRes = httpClient.send(completeReq, HttpResponse.BodyHandlers.ofString());
            if (completeRes.statusCode() != 200) {
                throw new TrustClientException("CLI login complete failed: HTTP " + completeRes.statusCode()
                        + " body=" + completeRes.body());
            }
            JsonNode complete = JSON.readTree(completeRes.body());
            String completeError = text(complete, "errorMessage");
            if (completeError != null && !completeError.isBlank()) {
                throw new TrustClientException("CLI login complete denied: " + completeError);
            }
            String tokenId = text(complete, "tokenId");
            if (tokenId == null || tokenId.isBlank()) {
                throw new TrustClientException("CLI login complete missing tokenId");
            }
            return new Result(tokenId, text(complete, "userId"), text(complete, "accountId"));
        } catch (TrustClientException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("CLI localhost login failed: " + e.getMessage(), e);
        } finally {
            if (server != null) {
                server.stop(0);
            }
        }
    }

    private static void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (Exception ignored) {
            // fall through
        }
        System.out.println("Open this URL to continue Trust login: " + url);
    }

    private record Callback(String code, String state) {
        static Callback fromQuery(String query) {
            String code = null;
            String state = null;
            if (query != null) {
                for (String part : query.split("&")) {
                    int eq = part.indexOf('=');
                    if (eq <= 0) {
                        continue;
                    }
                    String k = part.substring(0, eq);
                    String v = java.net.URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
                    if ("code".equals(k)) {
                        code = v;
                    } else if ("state".equals(k)) {
                        state = v;
                    }
                }
            }
            return new Callback(code, state);
        }
    }

    private static String text(JsonNode root, String field) {
        if (root == null) {
            return null;
        }
        JsonNode n = root.get(field);
        return n == null || n.isNull() ? null : n.asString();
    }

    private static String jsonQuote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String trimSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
