/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Private key secret.
 *
 * @author dhudson
 * 29/07/2026 - 11:48
 */
@NoArgsConstructor
@Setter
@Getter
@ToString
public class PrivateKey extends CryptoSecret {
    private String key;
}
