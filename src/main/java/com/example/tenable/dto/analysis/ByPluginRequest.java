package com.example.tenable.dto.analysis;

import lombok.Data;

import java.util.List;

/**
 * Request body for {@code POST /api/v1/vulnerabilities/by-plugin}.
 *
 * <p>{@code pluginIds} is required. {@code ipAddresses} is optional;
 * when provided it narrows results to only those hosts.
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
}
