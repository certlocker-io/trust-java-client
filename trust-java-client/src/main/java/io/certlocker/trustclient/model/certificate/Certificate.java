/*
 * Copyright (c) 2026.  Certlocker (tm)
 * All rights reserved
 */

package io.certlocker.trustclient.model.certificate;

import io.certlocker.trustclient.model.asset.AbstractAsset;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Certificate stored in Trust.
 */
@NoArgsConstructor
@Getter
@Setter
@ToString
public class Certificate extends AbstractAsset {

    private LocalDateTime expires;
    private String primaryDomain;
    private List<String> sanDomains;
    private LocalDateTime notBefore;
    private Integer entries;
    private String serialNumber;
    private String publicKeyAlgo;
    private Boolean merkleTreeCert;
    private String issuerCn;
    private String issuerO;
    private String fingerprintSha256;
    private String fingerprintSha1;
    private String publicCert;
    private String certificateProperties;
    private String privateKey;
    private CertificateValidation certValidation;
    private String linkId;
    private Integer percentRemaining;
}
