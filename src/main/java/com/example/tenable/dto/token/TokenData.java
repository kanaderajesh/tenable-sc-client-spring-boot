package com.example.tenable.dto.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenData {

    /** The session token — pass this as the {@code X-SecurityCenter} header value. */
    private long token;

    private boolean unassociatedCert;
    private String failedLoginIP;
    private String failedLogins;
    private String lastFailedLogin;
    private String lastLogin;
    private String lastLoginIP;
    private boolean releaseSession;
}
