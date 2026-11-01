/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

/**
 * Kind of secret stored in Trust.
 *
 * @author dhudson
 */
public enum SecretType {
    /** Private key material. */
    PRIVATE_KEY,
    /** PEM-encoded key/certificate material. */
    PEM,
    /** Password string. */
    PASSWORD,
    /** Username and password pair. */
    CREDENTIALS,
    /** Free-form configuration text. */
    CONFIGURATION;

    /**
     * Returns whether this secret type has a key algorithm.
     *
     * @return {@code true} for {@link #PRIVATE_KEY} and {@link #PEM}
     */
    public boolean hasAlgo() {
        return (this == PRIVATE_KEY || this == PEM);
    }
}
