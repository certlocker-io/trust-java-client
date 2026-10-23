package io.certlocker.trustclient.model.token;

import io.certlocker.trustclient.model.asset.AbstractAsset;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Access token stored in Trust.
 *
 * @author dhudson
 * 22/10/2026 - 14:31
 */
@NoArgsConstructor
@Setter
@Getter
@ToString
public class Token extends AbstractAsset {

    private Boolean singleUse;
    private List<Protocol> protocols;
    private TokenType tokenType;
    private List<String> hosts;
    private List<String> groupAccess;
    private String secretId;
    private String accessCode;
    private String bastionId;
    private String certId;
    private Boolean autoRotate;
    private String cidr;
    private String userId;
    private String agentId;
    private LocalDateTime startTime;
    private Integer percentRemaining;
}
