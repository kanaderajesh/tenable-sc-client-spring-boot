package com.example.tenable.dto;

import lombok.Builder;
import lombok.Data;

/**
 * A single row returned by the {@code POST /api/v1/vulnerabilities/by-plugin} endpoint.
 * Represents one plugin detection on one host, including the raw plugin output text.
 */
@Data
@Builder
public class PluginIpResult {

    private String pluginId;
    private String ipAddress;
    private String pluginText;
}
