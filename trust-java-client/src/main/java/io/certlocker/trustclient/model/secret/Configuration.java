package io.certlocker.trustclient.model.secret;

import lombok.*;

/**
 * Configuration secret. The secret value is the fetched secret contents.
 *
 * @author dhudson
 * 22/10/2026 - 13:43
 */
@Setter
@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Configuration {
    private String secret;
}
