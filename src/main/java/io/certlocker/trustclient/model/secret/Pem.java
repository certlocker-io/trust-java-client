/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * PEM secret, including the key material.
 *
 * @author dhudson
 * 01/02/2026 - 10:01
 */
@Setter
@Getter
@ToString
public class Pem extends CryptoSecret {
    private String username;
    private String key;

    /**
     * Creates an empty PEM secret for JSON binding.
     */
    public Pem() {
    }
}
