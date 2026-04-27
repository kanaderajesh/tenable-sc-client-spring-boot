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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * Rejects requests whose originating client is not on the configured allowlist.
 *
 * <p>Each entry in {@code tenable.sc.allowed-clients} may be an IP address,
 * a fully-qualified domain name, or a NetBIOS / short hostname (the first label
 * of the FQDN). Matching is case-insensitive.
 *
 * <p>The check is skipped when the list is empty, so existing deployments without
 * the config are unaffected.
 *
 * <p>Client identity resolution order:
 * <ol>
 *   <li>{@code X-Forwarded-For} header — first value, for reverse-proxy deployments</li>
 *   <li>{@code REMOTE_ADDR} — for direct connections</li>
 * </ol>
 *
 * <p>Once the client IP is known, a reverse-DNS lookup is performed to obtain the
 * hostname. The allowlist is then checked against all three candidates:
 * IP, FQDN, and NetBIOS short name (first DNS label). If reverse DNS fails the
 * lookup falls back to the IP string for both hostname checks.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ClientIpWhitelistInterceptor implements HandlerInterceptor {

    private final TenableProperties props;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        List<String> allowedClients = props.getAllowedClients();
        if (allowedClients.isEmpty()) {
            return true;
        }

        String clientIp = resolveClientIp(request);
        String hostname  = resolveHostname(clientIp);
        // NetBIOS / short name: first label of the FQDN (e.g. "myserver" from "myserver.example.com")
        String shortName = hostname.contains(".") ? hostname.split("\\.")[0] : hostname;

        List<String> lowerAllowed = allowedClients.stream()
                .map(String::toLowerCase)
                .toList();

        boolean permitted = lowerAllowed.contains(clientIp.toLowerCase())
                || lowerAllowed.contains(hostname.toLowerCase())
                || lowerAllowed.contains(shortName.toLowerCase());

        if (permitted) {
            return true;
        }

        log.warn("Blocked request from non-whitelisted client: ip={}, hostname={}", clientIp, hostname);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"Access denied: your IP address or hostname is not allowed\"}");
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

    /** Reverse-DNS lookup; returns the IP string itself if the lookup fails. */
    String resolveHostname(String ip) {
        try {
            return InetAddress.getByName(ip).getCanonicalHostName();
        } catch (UnknownHostException e) {
            return ip;
        }
    }
}
