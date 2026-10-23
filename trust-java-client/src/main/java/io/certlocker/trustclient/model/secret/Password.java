package io.certlocker.trustclient.model.secret;

import lombok.*;

/**
 * Password secret. The password value is the fetched secret contents.
 *
 * @author dhudson
 * 22/10/2026 - 13:41
 */
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@ToString
public class Password {

    private String password;
}
