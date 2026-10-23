/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.asset;

/**
 * Lifecycle status of a Trust asset.
 *
 * @author dhudson
 * 20/03/2026 - 07:54
 */
public enum AssetStatus {
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    REVOKED;

    /**
     * Returns whether the asset is active.
     *
     * @return {@code true} when the status is {@link #ACTIVE}
     */
    public boolean isActive() {
        return this == ACTIVE;
    }

    /**
     * Returns whether the asset can be suspended.
     *
     * @return {@code true} when the status is {@link #ACTIVE}
     */
    public boolean canSuspend() {
        return this == ACTIVE;
    }

    /**
     * Returns whether the asset can be revoked.
     *
     * @return {@code true} unless the status is already {@link #REVOKED}
     */
    public boolean canRevoke() {
        return (this != REVOKED);
    }

    /**
     * Returns whether a suspended asset can be resumed.
     *
     * @return {@code true} when the status is {@link #SUSPENDED}
     */
    public boolean canResume() {
        return (this == SUSPENDED);
    }

    /**
     * Returns whether the asset can be renewed.
     *
     * @return {@code true} when the status is {@link #ACTIVE} or {@link #EXPIRED}
     */
    public boolean canRenew() {
        return this == ACTIVE || this == EXPIRED;
    }

    /**
     * Returns whether the asset can be rotated.
     *
     * @return {@code true} when the status is {@link #ACTIVE} or {@link #EXPIRED}
     */
    public boolean canRotate() {
        return this == ACTIVE || this == EXPIRED;
    }
}
