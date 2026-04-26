package com.example.tenable.client;

import com.example.tenable.config.TenableProperties.EndpointConfig;
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
 * <p>Supports two authentication modes per endpoint:
 * <ul>
 *   <li><b>TOKEN</b> — POST /token to obtain a session token, DELETE /token to log out.
 *       Use {@link #createToken(EndpointConfig)} / {@link #buildTokenHeaders(long)} /
 *       {@link #deleteToken(long, EndpointConfig)}.</li>
 *   <li><b>API_KEY</b> — stateless; attach {@code x-apikey} on every request.
 *       Use {@link #buildApiKeyHeaders(EndpointConfig)}. No login/logout needed.</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenableAuthClient {

    private static final String TOKEN_PATH = "/rest/token";

    private final RestTemplate tenableRestTemplate;

    // -------------------------------------------------------------------------
    // Header builders
    // -------------------------------------------------------------------------

    /**
     * Builds the {@code X-SecurityCenter} header for a session token.
     * The token value comes from {@link #createToken(EndpointConfig)}.
     */
    public HttpHeaders buildTokenHeaders(long token) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-SecurityCenter", String.valueOf(token));
        return headers;
    }

    /**
     * Builds the {@code x-apikey} header for the given endpoint's API key credentials.
     *
     * <p>Header format: {@code x-apikey: accesskey=ACCESS_KEY; secretkey=SECRET_KEY}
     *
     * @throws IllegalStateException if accessKey or secretKey are missing on the endpoint
     */
    public HttpHeaders buildApiKeyHeaders(EndpointConfig endpoint) {
        String ak = endpoint.getAccessKey();
        String sk = endpoint.getSecretKey();
        if (ak == null || ak.isBlank() || sk == null || sk.isBlank()) {
            throw new IllegalStateException(
                    "accessKey and secretKey must both be set for API_KEY auth on endpoint: "
                            + endpoint.getBaseUrl());
        }
        log.debug("Using API key auth for {} (accessKey prefix: {}...)",
                endpoint.getBaseUrl(), ak.substring(0, Math.min(4, ak.length())));
        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", "accesskey=" + ak + "; secretkey=" + sk);
        return headers;
    }

    // -------------------------------------------------------------------------
    // Token lifecycle — TOKEN mode only
    // -------------------------------------------------------------------------

    /**
     * Authenticates against the given endpoint and returns a session token.
     *
     * @throws TenableApiException if the server returns an error response
     */
    public TokenData createToken(EndpointConfig endpoint) {
        String username = endpoint.getUsername();
        String password = endpoint.getPassword();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalStateException(
                    "username and password must both be set for TOKEN auth on endpoint: "
                            + endpoint.getBaseUrl());
        }

        String url = endpoint.getBaseUrl() + TOKEN_PATH;

        TokenRequest body = TokenRequest.builder()
                .username(username)
                .password(password)
                .releaseSession(true)
                .build();

        HttpHeaders headers = jsonHeaders();
        HttpEntity<TokenRequest> request = new HttpEntity<>(body, headers);

        log.debug("POST {} — authenticating as '{}'", url, endpoint.getUsername());

        ResponseEntity<TenableApiResponse<TokenData>> response = tenableRestTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<>() {}
        );

        TenableApiResponse<TokenData> apiResponse = requireSuccessBody(response);
        log.info("Authentication successful for {} — token acquired", endpoint.getBaseUrl());
        return apiResponse.getResponse();
    }

    /**
     * Logs out by deleting the session token from the given endpoint.
     *
     * @param token    the value previously returned by {@link #createToken(EndpointConfig)}
     * @param endpoint the endpoint to log out from
     */
    public void deleteToken(long token, EndpointConfig endpoint) {
        String url = endpoint.getBaseUrl() + TOKEN_PATH;

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

        log.info("Session token invalidated for {}", endpoint.getBaseUrl());
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
