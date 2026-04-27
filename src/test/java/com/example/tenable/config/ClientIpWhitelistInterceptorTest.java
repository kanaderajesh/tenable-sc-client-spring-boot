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

    // Spy so we can stub resolveHostname without triggering real DNS lookups
    ClientIpWhitelistInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = spy(new ClientIpWhitelistInterceptor(props));
    }

    // -------------------------------------------------------------------------
    // Empty allowlist
    // -------------------------------------------------------------------------

    @Test
    void emptyAllowlist_allowsAllRequests() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of());

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    // -------------------------------------------------------------------------
    // IP address matching
    // -------------------------------------------------------------------------

    @Test
    void allowedIp_isPermitted() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("10.0.0.1", "192.168.1.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        doReturn("10.0.0.1").when(interceptor).resolveHostname("10.0.0.1");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void blockedIp_returns403() throws Exception {
        StringWriter sw = new StringWriter();
        when(props.getAllowedClients()).thenReturn(List.of("10.0.0.1"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("1.2.3.4");
        doReturn("1.2.3.4").when(interceptor).resolveHostname("1.2.3.4");
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isFalse();
        verify(response).setStatus(403);
        assertThat(sw.toString()).contains("Access denied");
    }

    // -------------------------------------------------------------------------
    // Hostname (FQDN) matching
    // -------------------------------------------------------------------------

    @Test
    void allowedFqdn_isPermitted() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("myserver.example.com"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("myserver.example.com").when(interceptor).resolveHostname("10.0.0.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void fqdnMatchIsCaseInsensitive() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("MyServer.Example.COM"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("myserver.example.com").when(interceptor).resolveHostname("10.0.0.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void blockedHost_ipAndFqdnBothAbsent_returns403() throws Exception {
        StringWriter sw = new StringWriter();
        when(props.getAllowedClients()).thenReturn(List.of("allowed.example.com"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("blocked.example.com").when(interceptor).resolveHostname("10.0.0.5");
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isFalse();
        verify(response).setStatus(403);
    }

    // -------------------------------------------------------------------------
    // NetBIOS / short-name matching
    // -------------------------------------------------------------------------

    @Test
    void allowedShortName_matchesFirstDnsLabel() throws Exception {
        // Config contains just the NetBIOS name; reverse DNS returns the FQDN
        when(props.getAllowedClients()).thenReturn(List.of("MYSERVER"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("myserver.corp.example.com").when(interceptor).resolveHostname("10.0.0.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void shortNameMatchIsCaseInsensitive() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("myserver"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("MYSERVER.CORP.EXAMPLE.COM").when(interceptor).resolveHostname("10.0.0.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void reverseDnsFailure_fallsBackToIpForHostnameChecks() throws Exception {
        // When reverse DNS fails, resolveHostname returns the IP string.
        // If the IP is in the allowlist the request should still be permitted.
        when(props.getAllowedClients()).thenReturn(List.of("10.0.0.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        doReturn("10.0.0.5").when(interceptor).resolveHostname("10.0.0.5"); // simulates DNS failure

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    // -------------------------------------------------------------------------
    // X-Forwarded-For handling
    // -------------------------------------------------------------------------

    @Test
    void xForwardedFor_singleValue_usedAsClientIp() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("203.0.113.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5");
        doReturn("203.0.113.5").when(interceptor).resolveHostname("203.0.113.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void xForwardedFor_chainedProxies_firstValueIsClient() throws Exception {
        when(props.getAllowedClients()).thenReturn(List.of("203.0.113.5"));
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.5, 10.0.0.1, 10.0.0.2");
        doReturn("203.0.113.5").when(interceptor).resolveHostname("203.0.113.5");

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
    }

    @Test
    void xForwardedFor_notInAllowlist_returns403() throws Exception {
        StringWriter sw = new StringWriter();
        when(props.getAllowedClients()).thenReturn(List.of("10.0.0.1"));
        when(request.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 10.0.0.1");
        doReturn("1.2.3.4").when(interceptor).resolveHostname("1.2.3.4");
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isFalse();
        verify(response).setStatus(403);
    }

    // -------------------------------------------------------------------------
    // resolveClientIp unit tests
    // -------------------------------------------------------------------------

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
