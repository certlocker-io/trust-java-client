package io.certlocker.trustclient.auth;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Reads a 2FA / access code from stdin.
 */
public final class ConsoleAuthCodePrompt implements AuthCodePrompt {

    @Override
    public String prompt(String reason) throws Exception {
        System.out.print("Trust " + (reason == null ? "authentication code" : reason) + ": ");
        System.out.flush();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = reader.readLine();
        if (line == null || line.isBlank()) {
            throw new IllegalStateException("Empty authentication code");
        }
        return line.trim();
    }
}
