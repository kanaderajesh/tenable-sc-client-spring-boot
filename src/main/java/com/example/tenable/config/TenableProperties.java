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

    @NotBlank
    private String baseUrl;

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    private boolean sslVerificationDisabled = false;

    @Positive
    private int connectTimeout = 10_000;

    @Positive
    private int readTimeout = 60_000;

    @Positive
    private int defaultPageSize = 100;
}
