/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.token;

/**
 * What a token grants access to.
 */
public enum TokenType {
    CERTIFICATE,
    HOST,
    BASTION,
    SECRET,
    ROOT,
    MCP,
    WILDCARD
}
