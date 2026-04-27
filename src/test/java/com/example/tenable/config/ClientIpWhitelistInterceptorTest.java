package com.example.tenable.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientIpWhitelistInterceptorTest {

    @Mock TenableProperties props;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock Object handler;

    ClientIpWhitelistInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new ClientIpWhitelistInterceptor(props);
    }

    @Test
    void emptyAllowlist_allowsAllRequests() throws Exception {
        when(props.getAllowedClientIps()).thenReturn(List.of());

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void allowedIp_isPermitted() throws Exception {
        when(props.getAllowedClientIps()).thenReturn(List.of("10.0.0.1", "192.168.1.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void blockedIp_returns403() throws Exception {
        StringWriter sw = new StringWriter();
        when(props.getAllowedClientIps()).thenReturn(List.of("10.0.0.1"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("1.2.3.4");
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isFalse();
        verify(response).setStatus(403);
        assertThat(sw.toString()).contains("Access denied");
    }

    @Test
    void xForwardedFor_singleValue_usedAsClientIp() throws Exception {
        when(props.getAllowedClientIps()).thenReturn(List.of("203.0.113.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void xForwardedFor_chainedProxies_firstValueIsClient() throws Exception {
        when(props.getAllowedClientIps()).thenReturn(List.of("203.0.113.5"));
        // "client, proxy1, proxy2"
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5, 10.0.0.1, 10.0.0.2");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void xForwardedFor_notInAllowlist_returns403() throws Exception {
        StringWriter sw = new StringWriter();
        when(props.getAllowedClientIps()).thenReturn(List.of("10.0.0.1"));
        when(request.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 10.0.0.1");
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isFalse();
        verify(response).setStatus(403);
    }

    @Test
    void resolveClientIp_prefersXForwardedFor() {
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5");

        String ip = interceptor.resolveClientIp(request);

        assertThat(ip).isEqualTo("203.0.113.5");
        verify(request, never()).getRemoteAddr();
    }

    @Test
    void resolveClientIp_fallsBackToRemoteAddr_whenHeaderAbsent() {
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.0.1");

        String ip = interceptor.resolveClientIp(request);

        assertThat(ip).isEqualTo("192.168.0.1");
    }

    @Test
    void resolveClientIp_stripsWhitespace_fromXForwardedFor() {
        when(request.getHeader("X-Forwarded-For")).thenReturn("  10.0.0.5  , 10.0.0.1");

        String ip = interceptor.resolveClientIp(request);

        assertThat(ip).isEqualTo("10.0.0.5");
    }
}
