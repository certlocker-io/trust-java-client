package io.certlocker.trustclient.error;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Error returned by Trust.
 *
 * @author dhudson
 * 23/10/2026 - 10:50
 */
@Setter
@Getter
@ToString
public class TrustError {
    private String errorMessage;
    private int httpStatus;

    /**
     * Creates an empty error for JSON binding.
     */
    public TrustError() {
    }
}
