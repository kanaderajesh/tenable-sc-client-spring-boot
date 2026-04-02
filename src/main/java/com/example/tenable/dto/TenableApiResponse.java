package com.example.tenable.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

/**
 * Generic wrapper that Tenable Security Center returns for every API call.
 *
 * <pre>
 * {
 *   "type":       "regular",
 *   "response":   { ... },        // actual payload — type varies per endpoint
 *   "error_code": 0,
 *   "error_msg":  "",
 *   "warnings":   [],
 *   "timestamp":  1234567890
 * }
 * </pre>
 *
 * @param <T> the type of the {@code response} field
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class TenableApiResponse<T> {

    private String type;
    private T response;
    private int errorCode;
    private String errorMsg;
    private List<Object> warnings;
    private long timestamp;

    public boolean isSuccess() {
        return errorCode == 0;
    }
}
