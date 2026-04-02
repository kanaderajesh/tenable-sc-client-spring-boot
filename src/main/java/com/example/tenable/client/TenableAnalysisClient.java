package com.example.tenable.client;

import com.example.tenable.config.TenableProperties;
import com.example.tenable.dto.TenableApiResponse;
import com.example.tenable.dto.analysis.AnalysisRequest;
import com.example.tenable.dto.analysis.AnalysisResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

/**
 * Low-level HTTP client for the Tenable SC /rest/analysis endpoint.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenableAnalysisClient {

    private static final String ANALYSIS_PATH = "/rest/analysis";

    private final RestTemplate tenableRestTemplate;
    private final TenableProperties props;

    /**
     * Executes an analysis query and returns the raw API response.
     *
     * @param token   the active session token (from {@link TenableAuthClient#createToken()})
     * @param request the analysis request body
     * @return the {@code response} section of the Tenable API envelope
     * @throws TenableApiException if the server returns an error
     */
    public AnalysisResponse query(long token, AnalysisRequest request) {
        String url = props.getBaseUrl() + ANALYSIS_PATH;

        HttpHeaders headers = buildHeaders(token);
        HttpEntity<AnalysisRequest> httpRequest = new HttpEntity<>(request, headers);

        log.debug("POST {} — type={} sourceType={} offsets=[{},{}]",
                url, request.getType(), request.getSourceType(),
                request.getStartOffset(), request.getEndOffset());

        ResponseEntity<TenableApiResponse<AnalysisResponse>> response = tenableRestTemplate.exchange(
                url,
                HttpMethod.POST,
                httpRequest,
                new ParameterizedTypeReference<>() {}
        );

        TenableApiResponse<AnalysisResponse> body = response.getBody();
        if (body == null) {
            throw new TenableApiException("Empty response body from /analysis");
        }
        if (!body.isSuccess()) {
            throw new TenableApiException(
                    "Analysis query failed — error %d: %s".formatted(body.getErrorCode(), body.getErrorMsg()));
        }

        log.debug("Analysis returned {}/{} records",
                body.getResponse().getReturnedRecords(),
                body.getResponse().getTotalRecords());

        return body.getResponse();
    }

    /**
     * Convenience: pages through ALL records automatically, collecting every page.
     *
     * @param token    active session token
     * @param template the request template — {@code startOffset}/{@code endOffset} are managed here
     * @param pageSize number of records per page
     * @return all results concatenated across pages
     */
    public List<java.util.Map<String, Object>> queryAll(
            long token, AnalysisRequest template, int pageSize) {

        List<java.util.Map<String, Object>> all = new java.util.ArrayList<>();
        int start = 0;

        while (true) {
            AnalysisRequest page = buildPage(template, start, start + pageSize);
            AnalysisResponse chunk = query(token, page);

            if (chunk.getResults() != null) {
                all.addAll(chunk.getResults());
            }

            int fetched = all.size();
            int total   = chunk.getTotalRecords();
            log.info("Fetched {}/{} records", fetched, total);

            if (fetched >= total || chunk.getReturnedRecords() == 0) {
                break;
            }
            start += pageSize;
        }

        return all;
    }

    // -------------------------------------------------------------------------

    private HttpHeaders buildHeaders(long token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.set("X-SecurityCenter", String.valueOf(token));
        return headers;
    }

    private AnalysisRequest buildPage(AnalysisRequest template, int start, int end) {
        return AnalysisRequest.builder()
                .type(template.getType())
                .sourceType(template.getSourceType())
                .scanID(template.getScanID())
                .view(template.getView())
                .wasVuln(template.getWasVuln())
                .sortField(template.getSortField())
                .sortDir(template.getSortDir())
                .query(template.getQuery())
                .startOffset(start)
                .endOffset(end)
                .build();
    }
}
