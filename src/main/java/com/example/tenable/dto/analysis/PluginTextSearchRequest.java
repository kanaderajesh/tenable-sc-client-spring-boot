package com.example.tenable.dto.analysis;

import lombok.Data;

import java.util.List;

/**
 * Request body for {@code POST /api/v1/vulnerabilities/plugin-text-search}.
 *
 * <p>Tenable SC applies a server-side {@code pluginText} filter, so only records
 * whose plugin output contains the keyword are returned. This is more efficient
 * than client-side scanning for targeted single-keyword searches.
 *
 * <p>{@code keyword} is required. {@code filters} and {@code columns} are optional.
 */
@Data
public class PluginTextSearchRequest {

    /**
     * The text to search for inside plugin output. Tenable SC performs the match
     * server-side using {@code filterName=pluginText, operator==}. Required.
     */
    private String keyword;

    /**
     * Additional Tenable SC field filters combined with the pluginText filter (AND logic).
     * For example, restrict results to a specific severity or IP range.
     */
    private List<VulnerabilityFilter> filters;

    /**
     * Column names to include in each response record. Forwarded to Tenable SC so only
     * the requested fields are returned in the payload. Omit or send empty for all fields.
     */
    private List<String> columns;
}
