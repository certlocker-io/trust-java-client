/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Username and password secret.
 *
 * @author dhudson
 * 01/02/2026 - 10:00
 */
@Setter
@Getter
@ToString
public class Credentials {
    private String username;
    private String password;

    /**
     * Creates empty credentials for JSON binding.
     */
    public Credentials() {
    }

}
