package com.example.tenable.client;

/**
 * Thrown when the Tenable Security Center API returns a non-zero error code
 * or when the HTTP layer itself fails.
 */
public class TenableApiException extends RuntimeException {

    public TenableApiException(String message) {
        super(message);
    }

    public TenableApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
