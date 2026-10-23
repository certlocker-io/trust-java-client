/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.secret;

import io.certlocker.trustclient.model.asset.AbstractAsset;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Secret stored in Trust.
 */
@NoArgsConstructor
@Getter
@Setter
@ToString
public class Secret extends AbstractAsset {

    private SecretType secretType;
    private String secret;
    private Integer version;

}
