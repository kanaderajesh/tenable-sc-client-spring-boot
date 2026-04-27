package com.example.tenable.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.List;

/**
 * Rejects requests whose originating IP is not on the configured allowlist.
 *
 * <p>The check is skipped when {@code tenable.sc.allowed-client-ips} is empty,
 * so existing deployments without the config are unaffected.
 *
 * <p>IP resolution order:
 * <ol>
 *   <li>{@code X-Forwarded-For} header (first value, for reverse-proxy deployments)</li>
 *   <li>{@code REMOTE_ADDR} (direct connections)</li>
 * </ol>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ClientIpWhitelistInterceptor implements HandlerInterceptor {

    private final TenableProperties props;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        List<String> allowedIps = props.getAllowedClientIps();
        if (allowedIps.isEmpty()) {
            return true;
        }

        String clientIp = resolveClientIp(request);
        if (allowedIps.contains(clientIp)) {
            return true;
        }

        log.warn("Blocked request from non-whitelisted IP: {}", clientIp);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"Access denied: your IP address is not allowed\"}");
        return false;
    }

    String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // X-Forwarded-For may be a comma-separated chain; first entry is the originating client
            return forwarded.split(",")[0].strip();
        }
        return request.getRemoteAddr();
    }
}
