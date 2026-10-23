package io.certlocker.trustclient.error;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Certlocker error response decoded from a Trust failure.
 *
 * @author dhudson
 * 23/10/2026 - 11:57
 */
@Getter
@Setter
@NoArgsConstructor
@ToString
public class CLErrorException {

    private CLError error;
    private String message;

}
