package io.certlocker.trustclient.oidc;

import java.time.Instant;

/**
 * Result of {@code POST /rest/api/v1/oidc/exchange}.
 * {@link #tokenId()} is the value to send as {@code x-api-token}.
 *
 * @param tokenId     minted Trust API token id ({@code x-api-token})
 * @param expiresAt   token expiry instant, or {@code null} if the response omitted/unparsed it
 * @param tokenType   token type string from Gateway ({@code SECRET}, {@code CERTIFICATE}, or {@code MCP}), or {@code null}
 * @param accountId   tenant account id for Gateway paths, or {@code null} if omitted
 * @param principalId OIDC principal id that minted the token, or {@code null} if omitted
 */
public record OidcExchangeResult(String tokenId, Instant expiresAt, String tokenType, String accountId, String principalId) {
}
