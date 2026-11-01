package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.nio.file.Path;
import java.security.interfaces.EdECPrivateKey;
import java.util.Objects;

/**
 * Mints short-lived DEVICE OIDC JWTs ({@code alg=EdDSA}) for Gateway
 * {@code POST /rest/api/v1/oidc/exchange}.
 * <p>
 * Claim / header shape matches Trust {@code DeviceOidcVerifier} and fixer {@code OidcDeviceKeys}.
 */
public final class DeviceOidcJwt {

    private DeviceOidcJwt() {
    }

    /**
     * Mints a device JWT with {@link DeviceOidc#DEFAULT_TTL_MINUTES}.
     *
     * @param audience   per-account aud (e.g. {@link DeviceOidc#audienceForAccount(String)})
     * @param deviceId   stable device id (claim {@code device_id} and {@code sub})
     * @param privateKey Ed25519 private key from enrollment
     * @param keyId      optional JWT {@code kid}; null/blank omits the header
     * @return compact JWS serialization
     * @throws TrustClientException if claims are invalid or signing fails
     */
    public static String mint(String audience, String deviceId, EdECPrivateKey privateKey, String keyId)
            throws TrustClientException {
        return mint(audience, deviceId, privateKey, keyId, DeviceOidc.DEFAULT_TTL_MINUTES);
    }

    /**
     * Mints a short-lived device JWT using {@link DeviceOidc#DEVICE_ISSUER}.
     *
     * @param audience   per-account aud
     * @param deviceId   stable device id
     * @param privateKey Ed25519 private key
     * @param keyId      optional JWT {@code kid}
     * @param ttlMinutes lifetime (minimum 1)
     * @return compact JWS serialization
     * @throws TrustClientException if claims are invalid or signing fails
     */
    public static String mint(
            String audience,
            String deviceId,
            EdECPrivateKey privateKey,
            String keyId,
            int ttlMinutes) throws TrustClientException {
        return mint(DeviceOidc.DEVICE_ISSUER, audience, deviceId, privateKey, keyId, ttlMinutes);
    }

    /**
     * Mints a device JWT with an explicit issuer (defaults should be {@link DeviceOidc#DEVICE_ISSUER}).
     *
     * @param issuer     JWT {@code iss}
     * @param audience   JWT {@code aud} (per-account)
     * @param deviceId   enrolled device id ({@code device_id} claim and {@code sub})
     * @param privateKey Ed25519 private key used to sign ({@code alg=EdDSA})
     * @param keyId      optional JWT {@code kid}
     * @param ttlMinutes lifetime in minutes (minimum 1)
     * @return compact JWS serialization
     * @throws TrustClientException if required fields are blank or signing fails
     */
    public static String mint(
            String issuer,
            String audience,
            String deviceId,
            EdECPrivateKey privateKey,
            String keyId,
            int ttlMinutes) throws TrustClientException {
        Objects.requireNonNull(privateKey, "privateKey");
        if (issuer == null || issuer.isBlank()) {
            throw new TrustClientException("DEVICE issuer is required");
        }
        if (audience == null || audience.isBlank()) {
            throw new TrustClientException("DEVICE audience is required");
        }
        if (deviceId == null || deviceId.isBlank()) {
            throw new TrustClientException("deviceId is required");
        }
        try {
            JwtClaims claims = new JwtClaims();
            claims.setIssuer(issuer.trim());
            claims.setAudience(audience.trim());
            claims.setSubject(DeviceOidc.subjectForDevice(deviceId));
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setExpirationTimeMinutesInTheFuture(Math.max(1, ttlMinutes));
            claims.setClaim("device_id", deviceId.trim());

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(privateKey);
            if (keyId != null && !keyId.isBlank()) {
                jws.setKeyIdHeaderValue(keyId.trim());
            }
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.EDDSA);
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new TrustClientException("Failed to mint DEVICE JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Loads the private key from {@code privateKeyPath} and mints a device JWT.
     *
     * @param audience       per-account aud
     * @param deviceId       enrolled device id
     * @param privateKeyPath PKCS#8 PEM file path
     * @param keyId          optional JWT {@code kid}
     * @param ttlMinutes     lifetime in minutes
     * @return compact JWS serialization
     * @throws TrustClientException if the key cannot be loaded or minting fails
     */
    public static String mintFromFile(
            String audience,
            String deviceId,
            Path privateKeyPath,
            String keyId,
            int ttlMinutes) throws TrustClientException {
        EdECPrivateKey key = DeviceOidcPrivateKey.loadFromFile(privateKeyPath);
        return mint(audience, deviceId, key, keyId, ttlMinutes);
    }

    /**
     * Loads the private key from a PEM string and mints a device JWT.
     *
     * @param audience       per-account aud
     * @param deviceId       enrolled device id
     * @param privateKeyPem  PKCS#8 PEM string
     * @param keyId          optional JWT {@code kid}
     * @param ttlMinutes     lifetime in minutes
     * @return compact JWS serialization
     * @throws TrustClientException if the key cannot be loaded or minting fails
     */
    public static String mintFromPem(
            String audience,
            String deviceId,
            String privateKeyPem,
            String keyId,
            int ttlMinutes) throws TrustClientException {
        EdECPrivateKey key = DeviceOidcPrivateKey.loadFromPem(privateKeyPem);
        return mint(audience, deviceId, key, keyId, ttlMinutes);
    }
}
