/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.certificate;

/**
 * How a certificate was validated.
 *
 * @author dhudson
 * 06/05/2026 - 14:16
 */
public enum CertificateValidation {

    DV("Domain Validated"),
    OV("Organization Validated"),
    EV("Extended Validation"),
    SS("Self Signed"),
    UNKNOWN("Unknown");

    private String description;

    CertificateValidation(String description) {
        this.description = description;
    }

    /**
     * Returns the display name of this validation level.
     *
     * @return display name
     */
    public String getDescription() {
        return description;
    }
}
