package io.certlocker.trustclient.oidc;

import lombok.Builder;
import lombok.Getter;

import java.nio.file.Path;

/**
 * Inputs for DEVICE OIDC mint + Gateway exchange.
 * <p>
 * Provide either a private key path or a private key PEM string (path wins when both are set).
 * {@code keyId} is optional unless the enrolled principal has a non-blank {@code keyId} that must
 * match the JWT {@code kid}.
 * <p>
 * Built with the Lombok {@code builder()} factory. Fields are immutable.
 */
@Getter
@Builder(toBuilder = true, buildMethodName = "buildInternal")
public final class DeviceOidcConfig {

    /** Per-account audience, e.g. {@code https://trust.certlocker.io/oidc/<accountId>}. */
    private final String audience;

    /** Enrolled {@code device_id} claim value. */
    private final String deviceId;

    /** Path to PKCS#8 Ed25519 private key PEM from enroll download; may be {@code null}. */
    private final Path privateKeyPath;

    /** PKCS#8 Ed25519 private key PEM string; may be {@code null} when {@link #privateKeyPath} is set. */
    private final String privateKeyPem;

    /** Optional JWT {@code kid}; must match enrolled principal {@code keyId} when that field is set. */
    private final String keyId;

    /** JWT {@code iss}; defaults to {@link DeviceOidc#DEVICE_ISSUER}. */
    @Builder.Default
    private final String issuer = DeviceOidc.DEVICE_ISSUER;

    /** JWT lifetime in minutes; defaults to {@link DeviceOidc#DEFAULT_TTL_MINUTES}. */
    @Builder.Default
    private final int ttlMinutes = DeviceOidc.DEFAULT_TTL_MINUTES;

    /**
     * Creates an immutable DEVICE OIDC config. Prefer {@code DeviceOidcConfig.builder()}.
     *
     * @param audience       per-account audience
     * @param deviceId       enrolled device id
     * @param privateKeyPath private key file path, or {@code null}
     * @param privateKeyPem  private key PEM, or {@code null}
     * @param keyId          optional JWT {@code kid}
     * @param issuer         JWT issuer
     * @param ttlMinutes     JWT lifetime in minutes
     */
    private DeviceOidcConfig(
            String audience,
            String deviceId,
            Path privateKeyPath,
            String privateKeyPem,
            String keyId,
            String issuer,
            int ttlMinutes) {
        this.audience = audience;
        this.deviceId = deviceId;
        this.privateKeyPath = privateKeyPath;
        this.privateKeyPem = privateKeyPem;
        this.keyId = keyId;
        this.issuer = issuer != null ? issuer : DeviceOidc.DEVICE_ISSUER;
        this.ttlMinutes = ttlMinutes > 0 ? ttlMinutes : DeviceOidc.DEFAULT_TTL_MINUTES;
    }

    /**
     * Lombok builder with String/Path private-key helpers and validation on {@link #build()}.
     */
    public static class DeviceOidcConfigBuilder {

        /**
         * Creates a builder. Prefer {@code DeviceOidcConfig.builder()}.
         */
        public DeviceOidcConfigBuilder() {
        }

        /**
         * Sets the private key path.
         *
         * @param path PKCS#8 PEM file path, or {@code null}
         * @return this builder
         */
        public DeviceOidcConfigBuilder privateKeyPath(Path path) {
            this.privateKeyPath = path;
            return this;
        }

        /**
         * Sets the private key path from a filesystem path string (Gradle / env).
         * Blank or {@code null} clears the path.
         *
         * @param path path string, or blank/{@code null} to clear
         * @return this builder
         */
        public DeviceOidcConfigBuilder privateKeyPath(String path) {
            this.privateKeyPath = path == null || path.isBlank() ? null : Path.of(path.trim());
            return this;
        }

        /**
         * Validates required fields and builds an immutable config.
         *
         * @return validated config
         * @throws IllegalArgumentException if audience/deviceId are blank or no private key material is set
         */
        public DeviceOidcConfig build() {
            DeviceOidcConfig config = buildInternal();
            if (config.audience == null || config.audience.isBlank()) {
                throw new IllegalArgumentException("audience must not be blank");
            }
            if (config.deviceId == null || config.deviceId.isBlank()) {
                throw new IllegalArgumentException("deviceId must not be blank");
            }
            boolean hasPath = config.privateKeyPath != null;
            boolean hasPem = config.privateKeyPem != null && !config.privateKeyPem.isBlank();
            if (!hasPath && !hasPem) {
                throw new IllegalArgumentException("privateKeyPath or privateKeyPem is required");
            }
            return config;
        }
    }
}
