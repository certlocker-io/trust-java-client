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
    PRIVATE_KEY,
    PEM,
    PASSWORD,
    CREDENTIALS,
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
