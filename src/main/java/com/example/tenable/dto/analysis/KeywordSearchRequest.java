package com.example.tenable.dto.analysis;

import lombok.Data;

import java.util.List;

/**
 * Request body for {@code POST /api/v1/vulnerabilities/keyword-search}.
 *
 * <p>Tenable SC returns the vulnerability page specified by the {@code startOffset} /
 * {@code endOffset} query params. Each record's {@code pluginText} is then searched
 * for the supplied keywords; only matching records are included in the response.
 *
 * <p>{@code keywords} is required. {@code filters} and {@code columns} are optional.
 */
@Data
public class KeywordSearchRequest {

    /**
     * One or more keywords to search for inside each vulnerability's plugin output text.
     * Matching is case-insensitive. A record is included in the response when at least
     * one keyword is found. Required — must not be null or empty.
     *
     * <p>Supports 300+ keywords efficiently by converting each record's plugin text to
     * lower-case once and scanning all keywords in a single pass.
     */
    private List<String> keywords;

    /**
     * Optional Tenable SC field filters applied before the keyword search,
     * e.g. restrict to a severity level or a specific IP range.
     */
    private List<VulnerabilityFilter> filters;

    /**
     * Optional list of field names to return in each result's {@code fields} map.
     * When omitted or empty all available fields are returned.
     * {@code pluginText} is always fetched from Tenable SC for keyword matching
     * but only appears in {@code fields} when explicitly listed here.
     *
     * <p>Example: {@code ["pluginID", "ip", "severity", "pluginName", "pluginText"]}
     */
    private List<String> columns;
}
