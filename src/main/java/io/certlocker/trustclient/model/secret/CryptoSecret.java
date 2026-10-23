/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Key algorithm and size shared by PEM and private key secrets.
 *
 * @author dhudson
 * 30/07/2026 - 15:20
 */
@Setter
@Getter
@NoArgsConstructor
public abstract class CryptoSecret {

    private SecretKeyAlgorithm keyAlgorithm;
    private String keySize;

    /**
     * Returns whether the key algorithm is treated as post-quantum ready.
     * <p>
     * This is {@link SecretKeyAlgorithm#ED25519}.
     *
     * @return {@code true} when the algorithm is Ed25519
     */
    public boolean isPQReady() {
        if (keyAlgorithm == null) {
            return false;
        }

        return keyAlgorithm == SecretKeyAlgorithm.ED25519;
    }
}
