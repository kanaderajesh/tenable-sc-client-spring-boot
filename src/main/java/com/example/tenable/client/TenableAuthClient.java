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
 * <p>Responsibilities:
 * <ul>
 *   <li>POST /token  — obtain a session token</li>
 *   <li>DELETE /token — invalidate the session</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenableAuthClient {

    private static final String TOKEN_PATH = "/rest/token";

    private final RestTemplate tenableRestTemplate;
    private final TenableProperties props;

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
