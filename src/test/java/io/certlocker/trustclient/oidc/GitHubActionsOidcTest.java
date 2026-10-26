package io.certlocker.trustclient.oidc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class GitHubActionsOidcTest {

    @Test
    public void ambientUnavailableOutsideActions() {
        // Local unit tests do not set ACTIONS_ID_TOKEN_* — expect false.
        assertFalse(GitHubActionsOidc.isAvailable());
    }
}
