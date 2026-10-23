package io.certlocker.trustclient.model.asset;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Fields shared by Trust assets such as secrets, certificates and tokens.
 *
 * @author dhudson
 * 22/10/2026 - 13:59
 */
@NoArgsConstructor
@Getter
@Setter
@ToString
public abstract class AbstractAsset {
    private String id;
    private String accountId;
    private String name;
    private String description;
    private AssetStatus status;
    private List<String> groups;
    private String createdBy;
    private String updatedBy;
    private LocalDateTime dateCreated;
    private LocalDateTime dateUpdated;
    private String lockedBy;
    private LocalDateTime dateLocked;
}
