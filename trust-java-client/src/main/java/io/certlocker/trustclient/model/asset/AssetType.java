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
    HOST,
    SECRET,
    CERTIFICATE,
    TOKEN,
    BASTION,
    PROBE,
    AGENT,
    ACME_CLIENT,
    DNS_CLIENT,
    AUTOMATION,
    CHANNEL
}
