package io.certlocker.trustclient.auth;

/**
 * Interactive prompt for 2FA / access-code step-up on user-bound tokens.
 */
@FunctionalInterface
public interface AuthCodePrompt {

    /**
     * Prompts the user for an authentication / access code.
     *
     * @param reason human-readable reason (e.g. {@code "2FA required"} / {@code "access code required"})
     * @return the code entered by the user
     * @throws Exception if prompting fails or is cancelled
     */
    String prompt(String reason) throws Exception;
}
