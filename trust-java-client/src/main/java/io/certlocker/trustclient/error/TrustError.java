package io.certlocker.trustclient.error;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Error returned by Trust.
 *
 * @author dhudson
 * 23/10/2026 - 10:50
 */
@NoArgsConstructor
@Setter
@Getter
@ToString
public class TrustError {
    private String errorMessage;
    private int httpStatus;
}
