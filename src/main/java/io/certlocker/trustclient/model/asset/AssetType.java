/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.asset;

/**
 * Kind of asset stored in Trust.
 *
 * @author dhudson
 * 13/03/2026 - 08:52
 */
public enum AssetType {
    /** Host / machine asset. */
    HOST,
    /** Secret asset. */
    SECRET,
    /** Certificate asset. */
    CERTIFICATE,
    /** API token asset. */
    TOKEN,
    /** Bastion asset. */
    BASTION,
    /** Probe asset. */
    PROBE,
    /** Agent asset. */
    AGENT,
    /** ACME client asset. */
    ACME_CLIENT,
    /** DNS client asset. */
    DNS_CLIENT,
    /** Automation asset. */
    AUTOMATION,
    /** Notification / message channel asset. */
    CHANNEL
}
