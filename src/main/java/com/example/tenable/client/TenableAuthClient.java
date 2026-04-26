package com.example.tenable.client;

import com.example.tenable.config.TenableProperties;
import com.example.tenable.dto.TenableApiResponse;
import com.example.tenable.dto.token.TokenData;
import com.example.tenable.dto.token.TokenRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * Low-level HTTP client for the Tenable SC /token endpoint.
 *
 * <p>Supports two authentication modes controlled by {@code tenable.sc.auth-mode}:
 * <ul>
 *   <li><b>TOKEN</b> (default) — POST /token to obtain a session token, DELETE /token to log out.
 *       Use {@link #createToken()} / {@link #buildTokenHeaders(long)} / {@link #deleteToken(long)}.</li>
 *   <li><b>API_KEY</b> — stateless; attach {@code x-apikey} header on every request.
 *       Use {@link #buildApiKeyHeaders()}. No login/logout calls are needed.</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenableAuthClient {

    private static final String TOKEN_PATH = "/rest/token";

    private final RestTemplate tenableRestTemplate;
    private final TenableProperties props;

    // -------------------------------------------------------------------------
    // Header builders — used by VulnerabilityService to pass auth to clients
    // -------------------------------------------------------------------------

    /**
     * Builds the {@code X-SecurityCenter} header for a previously obtained session token.
     * Only used in {@link TenableProperties.AuthMode#TOKEN} mode.
     */
    public HttpHeaders buildTokenHeaders(long token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-SecurityCenter", String.valueOf(token));
        return headers;
    }

    /**
     * Builds the {@code x-apikey} header required by Tenable SC API key authentication.
     * Only used in {@link TenableProperties.AuthMode#API_KEY} mode.
     *
     * <p>Header format: {@code x-apikey: accesskey=ACCESS_KEY; secretkey=SECRET_KEY}
     *
     * @throws IllegalStateException if authMode is not API_KEY, or if access/secret keys are missing
     */
    public HttpHeaders buildApiKeyHeaders() {
        if (props.getAuthMode() != TenableProperties.AuthMode.API_KEY) {
            throw new IllegalStateException(
                    "buildApiKeyHeaders() called but tenable.sc.auth-mode is TOKEN");
        }
        String ak = props.getAccessKey();
        String sk = props.getSecretKey();
        if (ak == null || ak.isBlank() || sk == null || sk.isBlank()) {
            throw new IllegalStateException(
                    "tenable.sc.access-key and tenable.sc.secret-key must both be set when auth-mode=API_KEY");
        }
        log.debug("Using API key authentication (accessKey prefix: {}...)",
                ak.substring(0, Math.min(4, ak.length())));
        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", "accesskey=" + ak + "; secretkey=" + sk);
        return headers;
    }

    // -------------------------------------------------------------------------
    // Token lifecycle — TOKEN mode only
    // -------------------------------------------------------------------------

    /**
     * Authenticates with Tenable SC and returns the token data on success.
     *
     * @throws TenableApiException if the server returns an error response
     */
    public TokenData createToken() {
        String url = props.getBaseUrl() + TOKEN_PATH;

        TokenRequest body = TokenRequest.builder()
                .username(props.getUsername())
                .password(props.getPassword())
                .releaseSession(true)   // release any stale session
                .build();

        HttpHeaders headers = jsonHeaders();
        HttpEntity<TokenRequest> request = new HttpEntity<>(body, headers);

        log.debug("POST {} — authenticating as '{}'", url, props.getUsername());

        ResponseEntity<TenableApiResponse<TokenData>> response = tenableRestTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<>() {}
        );

        TenableApiResponse<TokenData> apiResponse = requireSuccessBody(response);
        log.info("Authentication successful — token acquired");
        return apiResponse.getResponse();
    }

    /**
     * Logs out by deleting the session token from Tenable SC.
     *
     * @param token the value previously returned by {@link #createToken()}
     */
    public void deleteToken(long token) {
        String url = props.getBaseUrl() + TOKEN_PATH;

        HttpHeaders headers = jsonHeaders();
        headers.set("X-SecurityCenter", String.valueOf(token));

        HttpEntity<Void> request = new HttpEntity<>(headers);

        log.debug("DELETE {} — logging out", url);

        tenableRestTemplate.exchange(
                url,
                HttpMethod.DELETE,
                request,
                new ParameterizedTypeReference<TenableApiResponse<Object>>() {}
        );

        log.info("Session token invalidated");
    }

    // -------------------------------------------------------------------------

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        return headers;
    }

    private <T> TenableApiResponse<T> requireSuccessBody(
            ResponseEntity<TenableApiResponse<T>> responseEntity) {

        TenableApiResponse<T> body = responseEntity.getBody();
        if (body == null) {
            throw new TenableApiException("Empty response body from Tenable SC");
        }
        if (!body.isSuccess()) {
            throw new TenableApiException(
                    "Tenable SC returned error %d: %s".formatted(body.getErrorCode(), body.getErrorMsg()));
        }
        return body;
    }
}
