package com.example.tenable.client;

import com.example.tenable.config.TenableProperties.EndpointConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class TenableAuthClientTest {

    @Mock RestTemplate restTemplate;

    TenableAuthClient client;

    @BeforeEach
    void setUp() {
        client = new TenableAuthClient(restTemplate);
    }

    // -------------------------------------------------------------------------
    // createToken — TOKEN mode credential validation
    // -------------------------------------------------------------------------

    @Test
    void createToken_missingUsername_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithTokenAuth(null, "password");

        assertThatThrownBy(() -> client.createToken(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username and password")
                .hasMessageContaining(endpoint.getBaseUrl());
    }

    @Test
    void createToken_blankUsername_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithTokenAuth("   ", "password");

        assertThatThrownBy(() -> client.createToken(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username and password");
    }

    @Test
    void createToken_missingPassword_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithTokenAuth("user", null);

        assertThatThrownBy(() -> client.createToken(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username and password");
    }

    @Test
    void createToken_blankPassword_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithTokenAuth("user", "");

        assertThatThrownBy(() -> client.createToken(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username and password");
    }

    // -------------------------------------------------------------------------
    // buildApiKeyHeaders — API_KEY mode credential validation
    // -------------------------------------------------------------------------

    @Test
    void buildApiKeyHeaders_missingAccessKey_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithApiKeyAuth(null, "secret");

        assertThatThrownBy(() -> client.buildApiKeyHeaders(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("accessKey and secretKey");
    }

    @Test
    void buildApiKeyHeaders_missingSecretKey_throwsIllegalState() {
        EndpointConfig endpoint = endpointWithApiKeyAuth("access", null);

        assertThatThrownBy(() -> client.buildApiKeyHeaders(endpoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("accessKey and secretKey");
    }

    @Test
    void buildApiKeyHeaders_validKeys_setsCorrectHeader() {
        EndpointConfig endpoint = endpointWithApiKeyAuth("my-access", "my-secret");

        var headers = client.buildApiKeyHeaders(endpoint);

        assertThat(headers.getFirst("x-apikey"))
                .isEqualTo("accesskey=my-access; secretkey=my-secret");
    }

    // -------------------------------------------------------------------------
    // buildTokenHeaders
    // -------------------------------------------------------------------------

    @Test
    void buildTokenHeaders_setsXSecurityCenterHeader() {
        var headers = client.buildTokenHeaders(999999L);

        assertThat(headers.getFirst("X-SecurityCenter")).isEqualTo("999999");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private EndpointConfig endpointWithTokenAuth(String username, String password) {
        EndpointConfig e = new EndpointConfig();
        e.setBaseUrl("https://sc.example.com");
        e.setUsername(username);
        e.setPassword(password);
        return e;
    }

    private EndpointConfig endpointWithApiKeyAuth(String accessKey, String secretKey) {
        EndpointConfig e = new EndpointConfig();
        e.setBaseUrl("https://sc.example.com");
        e.setAccessKey(accessKey);
        e.setSecretKey(secretKey);
        return e;
    }
}
