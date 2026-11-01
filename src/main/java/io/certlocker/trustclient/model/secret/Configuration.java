package io.certlocker.trustclient.model.secret;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Configuration secret. The secret value is the fetched secret contents.
 *
 * @author dhudson
 * 22/10/2026 - 13:43
 */
@Setter
@Getter
@ToString
@AllArgsConstructor
public class Configuration {
    private String secret;

    /**
     * Creates an empty configuration secret for JSON binding.
     */
    public Configuration() {
    }
}
