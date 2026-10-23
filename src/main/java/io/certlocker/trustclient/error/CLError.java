package io.certlocker.trustclient.error;

import com.fasterxml.jackson.annotation.JsonTypeName;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Error body carried by a Certlocker error response.
 *
 * @author dhudson
 * 23/10/2026 - 11:57
 */
@Setter
@Getter
@JsonTypeName(value = "error")
@ToString
public class CLError {

    private String message;
}
