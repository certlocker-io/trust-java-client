package io.certlocker.trustclient.exception;

import io.certlocker.trustclient.error.TrustError;

/**
 * Failure returned by Trust, or a failure while calling Trust.
 *
 * @author dhudson
 * 23/10/2026 - 10:39
 */
public class TrustClientException extends Exception {

    private final TrustError error;

    /**
     * Creates an exception with a message and no {@link TrustError}.
     *
     * @param message detail message
     */
    public TrustClientException(String message) {
        super(message);
        this.error = null;
    }

    /**
     * Creates an exception with a message and a cause, and no {@link TrustError}.
     *
     * @param message detail message
     * @param cause underlying failure
     */
    public TrustClientException(String message, Throwable cause) {
        super(message, cause);
        this.error = null;
    }

    /**
     * Creates an exception from a Trust error response.
     *
     * @param error error returned by Trust
     */
    public TrustClientException(TrustError error) {
        super(error.getErrorMessage());
        this.error = error;
    }

    /**
     * Returns the Trust error response.
     *
     * @return the error, or {@code null} when the failure happened before a response was read
     */
    public TrustError getError() {
        return error;
    }

    /**
     * Returns whether this exception carries a {@link TrustError}.
     *
     * @return {@code true} when {@link #getError()} is present
     */
    public boolean hasError() {
        return error != null;
    }
}
