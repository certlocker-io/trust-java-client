/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

/**
 * Public-key algorithm for generated SSH PEM secrets.
 *
 * @author dhudson
 */
public enum SecretKeyAlgorithm {
    /** RSA. */
    RSA,
    /** Elliptic Curve Digital Signature Algorithm. */
    ECDSA,
    /** Ed25519. */
    ED25519
}
