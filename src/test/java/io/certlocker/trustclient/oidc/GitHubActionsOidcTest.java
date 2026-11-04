package io.certlocker.trustclient.oidc;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GitHubActionsOidcTest {
    @Test
    public void detectsAmbientCredentialsFromEnvironment() {
        String url = System.getenv(GitHubActionsOidc.REQUEST_URL_ENV);
        String token = System.getenv(GitHubActionsOidc.REQUEST_TOKEN_ENV);
        boolean present = url != null && !url.isBlank() && token != null && !token.isBlank();
        assertEquals(present, GitHubActionsOidc.isAvailable());
    }
}
