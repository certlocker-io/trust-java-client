/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import lombok.*;

/**
 * Username and password secret.
 *
 * @author dhudson
 * 01/02/2026 - 10:00
 */
@NoArgsConstructor
@Setter
@Getter
@ToString
public class Credentials {
    private String username;
    private String password;

}
