package com.example.tenable.dto.analysis;

import lombok.Data;

import java.util.List;

/**
 * Request body for {@code POST /api/v1/vulnerabilities/by-plugin}.
 *
 * <p>{@code pluginIds} is required. {@code ipAddresses} and {@code columns} are optional.
 */
@Data
public class ByPluginRequest {

    /** One or more Tenable plugin IDs to search for (required). */
    private List<String> pluginIds;

    /**
     * Optional list of IP addresses to restrict results to.
     * When omitted or empty all hosts are included.
     */
    private List<String> ipAddresses;

    /**
     * Optional list of Tenable SC field names to return in each result row.
     * When omitted or empty all available fields are returned.
     *
     * <p>Example: {@code ["pluginID", "ip", "severity", "pluginText"]}
     */
    private List<String> columns;
}
