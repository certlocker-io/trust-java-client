package io.certlocker.trustclient.oidc;

import java.time.Instant;

/**
 * Result of {@code POST /rest/api/v1/oidc/exchange}.
 * {@link #tokenId()} is the value to send as {@code x-api-token}.
 */
public record OidcExchangeResult(String tokenId, Instant expiresAt, String tokenType, String accountId, String principalId) {
}
