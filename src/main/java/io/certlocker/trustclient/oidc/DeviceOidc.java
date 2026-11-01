package io.certlocker.trustclient.oidc;

/**
 * Constants and helpers for CertLocker DEVICE OIDC (Ed25519 / {@code alg=EdDSA}).
 * <p>
 * Claim shape matches Trust {@code DeviceOidcVerifier} / fixer {@code OidcDeviceKeys}:
 * {@code iss} = {@link #DEVICE_ISSUER}, {@code aud} = per-account audience,
 * {@code sub} = {@code device:<deviceId>}, claim {@code device_id}, header {@code kid} optional.
 */
public final class DeviceOidc {

    /**
     * Device / machine issuer ({@code iss}) for enrolled laptop/VPS JWTs.
     * Matches Trust {@code OidcAudiences.DEVICE_ISSUER}.
     */
    public static final String DEVICE_ISSUER = "https://trust.certlocker.io/oidc/device";

    /** Default short-lived JWT lifetime used when minting for exchange. */
    public static final int DEFAULT_TTL_MINUTES = 5;

    private DeviceOidc() {
    }

    /**
     * Builds the per-account audience URL {@code https://trust.certlocker.io/oidc/<accountId>}.
     *
     * @param accountId tenant account id (non-blank)
     * @return audience URL for DEVICE / GHA federation
     * @throws IllegalArgumentException if {@code accountId} is null or blank
     */
    public static String audienceForAccount(String accountId) {
        if (accountId == null || accountId.isBlank()) {
            throw new IllegalArgumentException("accountId is required");
        }
        return "https://trust.certlocker.io/oidc/" + accountId.trim();
    }

    /**
     * Builds the JWT {@code sub} claim for a device id ({@code device:<deviceId>}).
     *
     * @param deviceId enrolled device id (non-blank)
     * @return subject claim value
     * @throws IllegalArgumentException if {@code deviceId} is null or blank
     */
    public static String subjectForDevice(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("deviceId is required");
        }
        return "device:" + deviceId.trim();
    }
}
