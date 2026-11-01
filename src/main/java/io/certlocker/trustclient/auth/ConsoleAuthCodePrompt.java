package io.certlocker.trustclient.auth;

import java.util.Scanner;

/**
 * Reads a 2FA / access code from stdin ({@link Scanner} on {@code System.in}).
 * <p>
 * For live tests, run with a real stdin (terminal or IDE “Allow input from stdin”).
 */
public final class ConsoleAuthCodePrompt implements AuthCodePrompt {

    /**
     * Creates a console prompt that reads from {@code System.in}.
     */
    public ConsoleAuthCodePrompt() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String prompt(String reason) throws Exception {
        String label = reason == null || reason.isBlank() ? "authentication code" : reason.trim();
        System.out.print("Trust " + label + ": ");
        System.out.flush();

        Scanner scanner = new Scanner(System.in);
        String line = scanner.hasNextLine() ? scanner.nextLine() : null;
        if (line == null || line.isBlank()) {
            throw new IllegalStateException("Empty authentication code");
        }
        return line.trim();
    }
}
