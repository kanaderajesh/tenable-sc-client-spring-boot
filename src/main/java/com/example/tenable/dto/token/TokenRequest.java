package com.example.tenable.dto.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenRequest {

    private String username;
    private String password;

    /** Set true to release an existing session for this user before creating a new one. */
    @JsonProperty("releaseSession")
    @Builder.Default
    private boolean releaseSession = false;
}
