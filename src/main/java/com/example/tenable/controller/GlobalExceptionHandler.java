package com.example.tenable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.util.Map;

/**
 * Translates low-level HTTP/connectivity errors into clean JSON error responses.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<Map<String, String>> handleConnectivity(ResourceAccessException ex) {
        log.error("Cannot reach Tenable SC: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", "Cannot reach Tenable Security Center: " + ex.getMessage()));
    }

    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<Map<String, String>> handleClientError(HttpClientErrorException ex) {
        log.error("Tenable SC client error {}: {}", ex.getStatusCode(), ex.getMessage());
        return ResponseEntity.status(ex.getStatusCode())
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(HttpServerErrorException.class)
    public ResponseEntity<Map<String, String>> handleServerError(HttpServerErrorException ex) {
        log.error("Tenable SC server error {}: {}", ex.getStatusCode(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(Map.of("error", "Tenable SC returned an error: " + ex.getMessage()));
    }
}
