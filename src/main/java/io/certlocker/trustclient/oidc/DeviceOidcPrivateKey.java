package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Loads an Ed25519 private key from PKCS#8 PEM (as downloaded by ui-edge DEVICE enroll).
 * <p>
 * Accepts {@code -----BEGIN PRIVATE KEY-----} PEM from a file path or string.
 * Private keys stay on the machine — never check them into source control.
 */
public final class DeviceOidcPrivateKey {

    private DeviceOidcPrivateKey() {
    }

    /**
     * Loads an Ed25519 private key from a PEM file path.
     *
     * @param path path to PKCS#8 PEM written at enrollment
     * @return Ed25519 private key
     * @throws TrustClientException if the file cannot be read or is not Ed25519 PKCS#8
     */
    public static EdECPrivateKey loadFromFile(Path path) throws TrustClientException {
        Objects.requireNonNull(path, "path");
        try {
            String pem = Files.readString(path, StandardCharsets.UTF_8);
            return loadFromPem(pem);
        } catch (IOException e) {
            throw new TrustClientException("Failed to read DEVICE private key from " + path + ": " + e.getMessage(), e);
        }
    }

    /**
     * Loads an Ed25519 private key from a PEM file path string.
     *
     * @param path path to PKCS#8 PEM written at enrollment
     * @return Ed25519 private key
     * @throws TrustClientException if the path is blank, unreadable, or not Ed25519 PKCS#8
     */
    public static EdECPrivateKey loadFromFile(String path) throws TrustClientException {
        Objects.requireNonNull(path, "path");
        if (path.isBlank()) {
            throw new TrustClientException("DEVICE private key path must not be blank");
        }
        return loadFromFile(Path.of(path.trim()));
    }

    /**
     * Loads an Ed25519 private key from a PKCS#8 PEM string
     * ({@code -----BEGIN PRIVATE KEY-----} …).
     *
     * @param pem PKCS#8 PEM as produced by ui-edge enroll download
     * @return Ed25519 private key
     * @throws TrustClientException if the PEM is missing, malformed, or not Ed25519
     */
    public static EdECPrivateKey loadFromPem(String pem) throws TrustClientException {
        if (pem == null || pem.isBlank()) {
            throw new TrustClientException("DEVICE private key PEM is required");
        }
        String trimmed = pem.trim();
        if (!trimmed.contains("BEGIN PRIVATE KEY")) {
            throw new TrustClientException(
                    "DEVICE private key must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----); "
                            + "OpenSSL/encrypted or OpenSSH formats are not supported");
        }
        try {
            byte[] der = Base64.getDecoder().decode(stripPem(trimmed));
            PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
            if (!(key instanceof EdECPrivateKey ed)) {
                throw new TrustClientException("DEVICE private key must be Ed25519 PKCS#8");
            }
            NamedParameterSpec params = ed.getParams();
            if (params == null || !"Ed25519".equals(params.getName())) {
                throw new TrustClientException("DEVICE private key must be Ed25519 (found "
                        + (params == null ? "null" : params.getName()) + ")");
            }
            return ed;
        } catch (TrustClientException e) {
            throw e;
        } catch (Exception e) {
            throw new TrustClientException("Invalid DEVICE private key PEM: " + e.getMessage(), e);
        }
    }

    private static String stripPem(String pem) {
        return pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
    }
}
