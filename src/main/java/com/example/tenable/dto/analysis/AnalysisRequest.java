package com.example.tenable.dto.analysis;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * Request body for POST /analysis.
 *
 * <p>Minimal example for cumulative vulnerability data:
 * <pre>
 * {
 *   "type":        "vuln",
 *   "sourceType":  "cumulative",
 *   "startOffset": 0,
 *   "endOffset":   100,
 *   "query": {
 *     "type":   "vuln",
 *     "tool":   "vulndetails",
 *     "filters": []
 *   }
 * }
 * </pre>
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AnalysisRequest {

    /** "vuln" | "event" | "user" | "scLog" | "mobile" */
    private String type;

    /** "individual" | "cumulative" | "patched" (required when type=vuln) */
    private String sourceType;

    /** Required when sourceType="individual" */
    private Long scanID;

    /** Required when sourceType="individual" — "all" | "new" | "patched" */
    private String view;

    /** Optional — "onlyWas" | "excludeWas" | "includeWas" */
    private String wasVuln;

    /** Pagination — 0-based start index */
    @Builder.Default
    private int startOffset = 0;

    /** Pagination — exclusive end index */
    @Builder.Default
    private int endOffset = 100;

    /** Optional sort field name */
    private String sortField;

    /** Optional — "ASC" | "DESC" */
    private String sortDir;

    /**
     * Filter / query object. Use a plain {@code Map} for ad-hoc filters or
     * define a typed class and replace this field.
     *
     * <p>Typical vulnerability query:
     * <pre>
     * {
     *   "type":    "vuln",
     *   "tool":    "vulndetails",
     *   "filters": []
     * }
     * </pre>
     */
    private Map<String, Object> query;
}
