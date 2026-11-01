package io.certlocker.trustclient.model.secret;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Password secret. The password value is the fetched secret contents.
 *
 * @author dhudson
 * 22/10/2026 - 13:41
 */
@AllArgsConstructor
@Setter
@Getter
@ToString
public class Password {

    private String password;

    /**
     * Creates an empty password secret for JSON binding.
     */
    public Password() {
    }
}
