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
    RSA,
    ECDSA,
    ED25519
}
