package com.example.tenable.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * A single result row returned by the keyword-search endpoint.
 *
 * <p>{@code fields} contains the requested column values for the vulnerability record.
 * {@code matchedKeywords} lists every keyword from the request that was found inside
 * the record's plugin output text (case-insensitive match, original casing preserved).
 */
@Data
@Builder
public class KeywordMatchResult {

    /** Column values for this vulnerability record, keyed by field name. */
    private Map<String, Object> fields;

    /** Keywords from the request that matched in this record's plugin output text. */
    private List<String> matchedKeywords;
}
