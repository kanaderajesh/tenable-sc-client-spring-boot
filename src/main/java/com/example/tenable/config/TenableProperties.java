package com.example.tenable.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;

import java.util.HashMap;
import java.util.Map;

@Data
@Validated
@Component
@ConfigurationProperties(prefix = "tenable.sc")
public class TenableProperties {

    public enum AuthMode { TOKEN, API_KEY }

    /**
     * Configured Security Center endpoints, keyed by region name (e.g. APAC, EMEA, AMER).
     *
     * <p>Example YAML:
     * <pre>
     * tenable.sc:
     *   auth-mode: API_KEY          # global default
     *   endpoints:
     *     APAC:
     *       base-url: https://sc-apac.example.com
     *       access-key: ak-apac
     *       secret-key: sk-apac
     *     EMEA:
     *       base-url: https://sc-emea.example.com
     *       access-key: ak-emea
     *       secret-key: sk-emea
     *     AMER:
     *       base-url: https://sc-amer.example.com
     *       username: admin
     *       password: secret
     *       auth-mode: TOKEN        # per-endpoint override
     * </pre>
     */
    @Valid
    @NotEmpty
    private Map<String, EndpointConfig> endpoints = new HashMap<>();

    /** Default auth mode applied to any endpoint that does not set its own. */
    private AuthMode authMode = AuthMode.TOKEN;

    private boolean sslVerificationDisabled = false;

    @Positive
    private int connectTimeout = 10_000;

    @Positive
    private int readTimeout = 60_000;

    @Positive
    private int defaultPageSize = 1000;

    /**
     * Returns the endpoint config for the given region (case-insensitive).
     *
     * @throws IllegalArgumentException if no endpoint is configured for the region
     */
    public EndpointConfig getEndpoint(String region) {
        EndpointConfig config = endpoints.get(region.toUpperCase());
        if (config == null) {
            throw new IllegalArgumentException(
                    "No endpoint configured for region '%s'. Known regions: %s"
                            .formatted(region, endpoints.keySet()));
        }
        return config;
    }

    /**
     * Returns the effective auth mode for an endpoint:
     * the endpoint's own authMode if explicitly set, otherwise the global default.
     */
    public AuthMode effectiveAuthMode(EndpointConfig endpoint) {
        return endpoint.getAuthMode() != null ? endpoint.getAuthMode() : authMode;
    }

    @Data
    @Validated
    public static class EndpointConfig {

        @NotBlank
        private String baseUrl;

        /** Required when effective auth mode is TOKEN. */
        private String username;

        /** Required when effective auth mode is TOKEN. */
        private String password;

        /** Required when effective auth mode is API_KEY. */
        private String accessKey;

        /** Required when effective auth mode is API_KEY. */
        private String secretKey;

        /** Per-endpoint auth mode override. Null means inherit the global default. */
        private AuthMode authMode;
    }
}
