package com.example.tenable.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@Data
@Validated
@Component
@ConfigurationProperties(prefix = "tenable.sc")
public class TenableProperties {

    public enum AuthMode { TOKEN, API_KEY }

    @NotBlank
    private String baseUrl;

    /** Required only when authMode=TOKEN */
    private String username;

    /** Required only when authMode=TOKEN */
    private String password;

    private AuthMode authMode = AuthMode.TOKEN;

    /** Required when authMode=API_KEY */
    private String accessKey;

    /** Required when authMode=API_KEY */
    private String secretKey;

    private boolean sslVerificationDisabled = false;

    @Positive
    private int connectTimeout = 10_000;

    @Positive
    private int readTimeout = 60_000;

    @Positive
    private int defaultPageSize = 100;
}
