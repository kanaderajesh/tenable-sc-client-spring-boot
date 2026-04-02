package com.example.tenable.dto.analysis;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * The {@code response} payload returned inside {@link com.example.tenable.dto.TenableApiResponse}
 * for POST /analysis calls.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AnalysisResponse {

    private int totalRecords;
    private int returnedRecords;
    private int startOffset;
    private int endOffset;

    /**
     * Each element is a vulnerability/event/user record.
     * Keys depend on the query {@code tool} value (e.g. "vulndetails", "sumip", "sumid", …).
     * Using {@code Map<String, Object>} keeps the client flexible without requiring a DTO
     * for every possible field combination.
     */
    private List<Map<String, Object>> results;
}
