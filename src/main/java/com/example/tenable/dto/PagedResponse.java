package com.example.tenable.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

/**
 * Uniform pagination envelope returned by every vulnerability endpoint.
 *
 * <p>Callers use {@code startOffset} and {@code endOffset} to request the next page,
 * and {@code totalRecords} to determine when all pages have been fetched.
 *
 * @param <T> the type of the {@code results} payload
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PagedResponse<T> {

    /** Inclusive start index of this page (0-based). */
    private int startOffset;

    /** Exclusive end index of this page. */
    private int endOffset;

    /** Total number of matching records available on the server. */
    private int totalRecords;

    /** Number of records returned in this page. */
    private int returnedRecords;

    /** The payload for this page. */
    private T results;
}
