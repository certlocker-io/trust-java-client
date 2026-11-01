/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.token;

/**
 * Protocol a token is allowed to use.
 */
public enum Protocol {
    /** SSH access. */
    SSH,
    /** SFTP file transfer. */
    SFTP,
    /** HTTPS API / fetch. */
    HTTPS,
    /** ACME certificate automation. */
    ACME,
    /** Model Context Protocol. */
    MCP,
    /** Remote Desktop Protocol. */
    RDP,
    /** VNC remote desktop. */
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
