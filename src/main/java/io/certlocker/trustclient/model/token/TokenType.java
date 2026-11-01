/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.token;

/**
 * What a token grants access to.
 */
public enum TokenType {
    /** Certificate asset token. */
    CERTIFICATE,
    /** Host asset token. */
    HOST,
    /** Bastion access token. */
    BASTION,
    /** Secret asset token. */
    SECRET,
    /** Root / elevated token. */
    ROOT,
    /** MCP protocol token. */
    MCP,
    /** Wildcard token spanning multiple assets. */
    WILDCARD
}
