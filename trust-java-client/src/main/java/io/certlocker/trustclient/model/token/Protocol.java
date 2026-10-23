/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.token;

/**
 * Protocol a token is allowed to use.
 */
public enum Protocol {
    SSH,
    SFTP,
    HTTPS,

    ACME,
    MCP,
    RDP,
    VNC;

    /**
     * Returns whether this protocol is SSH or SFTP.
     *
     * @return {@code true} for {@link #SSH} and {@link #SFTP}
     */
    public boolean isSshFamily() {
        return this == SSH || this == SFTP;
    }
}
