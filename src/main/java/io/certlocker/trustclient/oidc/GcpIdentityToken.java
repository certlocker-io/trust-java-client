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
import java.util.concurrent.atomic.AtomicReference;

/**
 * Obtains a Google identity token for a Trust per-account audience from the GCE/GKE/Cloud Run
 * metadata server (Workload Identity / default service account).
 * <p>
 * Metadata path:
 * {@code /computeMetadata/v1/instance/service-accounts/default/identity?audience=…&format=full}
 * with header {@code Metadata-Flavor: Google}.
 */
public final class GcpIdentityToken {

    /** Default metadata host used on GCE / GKE / Cloud Run. */
    public static final String DEFAULT_METADATA_HOST = "metadata.google.internal";

    /** Env override for the metadata host (Google client libraries convention). */
    public static final String METADATA_HOST_ENV = "GCE_METADATA_HOST";

    /** Cloud Run service name — ambient signal that metadata identity tokens are available. */
    public static final String CLOUD_RUN_SERVICE_ENV = "K_SERVICE";

    private static final String IDENTITY_PATH =
            "/computeMetadata/v1/instance/service-accounts/default/identity";

    private static final AtomicReference<Boolean> availableCache = new AtomicReference<>();

    private GcpIdentityToken() {
    }

    /**
     * Returns whether this process appears to be on GCP with a reachable metadata identity endpoint.
     * Uses Cloud Run / metadata-host env as a fast positive signal, otherwise a short metadata probe
     * (cached for the JVM lifetime).
     *
     * @return {@code true} when a GCP identity token can likely be requested
     */
    public static boolean isAvailable() {
        if (nonBlank(System.getenv(CLOUD_RUN_SERVICE_ENV))
                || nonBlank(System.getenv(METADATA_HOST_ENV))) {
            return true;
        }
        Boolean cached = availableCache.get();
        if (cached != null) {
            return cached;
        }
        boolean ok = probeMetadata();
        availableCache.compareAndSet(null, ok);
        return ok;
    }

    /**
     * Fetches a Google identity token with the given audience (per-account Trust audience).
     *
     * @param audience e.g. {@code https://trust.certlocker.io/oidc/<accountId>}
     * @return raw JWT
     * @throws TrustClientException if the metadata request fails or returns empty
     */
    public static String requestIdToken(String audience) throws TrustClientException {
        return requestIdToken(audience, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build());
    }

    /**
     * Fetches a Google identity token using the supplied HTTP client.
     *
     * @param audience   e.g. {@code https://trust.certlocker.io/oidc/<accountId>}
     * @param httpClient client used for the metadata request
     * @return raw JWT
     * @throws TrustClientException if the metadata request fails or returns empty
     */
    public static String requestIdToken(String audience, HttpClient httpClient) throws TrustClientException {
        if (!nonBlank(audience)) {
            throw new TrustClientException("OIDC audience is required");
        }
        String url = metadataBase()
                + IDENTITY_PATH
                + "?audience=" + URLEncoder.encode(audience.trim(), StandardCharsets.UTF_8)
                + "&format=full";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Metadata-Flavor", "Google")
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new TrustClientException("GCP identity token request failed: HTTP " + response.statusCode()
                        + " body=" + truncate(response.body()));
            }
            String jwt = response.body();
            if (jwt == null || jwt.isBlank()) {
                throw new TrustClientException("GCP identity token response empty");
            }
            return jwt.trim();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustClientException("GCP identity token request failed: " + e.getMessage(), e);
        }
    }

    private static boolean probeMetadata() {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(200)).build();
            String url = metadataBase() + "/computeMetadata/v1/";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(400))
                    .header("Metadata-Flavor", "Google")
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static String metadataBase() {
        String host = System.getenv(METADATA_HOST_ENV);
        if (!nonBlank(host)) {
            host = DEFAULT_METADATA_HOST;
        }
        host = host.trim();
        if (host.startsWith("http://") || host.startsWith("https://")) {
            return host.endsWith("/") ? host.substring(0, host.length() - 1) : host;
        }
        return "http://" + host;
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
