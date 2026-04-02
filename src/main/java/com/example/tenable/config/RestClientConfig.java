package com.example.tenable.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class RestClientConfig {

    private final TenableProperties props;

    @Bean
    public RestTemplate tenableRestTemplate() throws Exception {
        HttpComponentsClientHttpRequestFactory factory;

        if (props.isSslVerificationDisabled()) {
            log.warn("SSL verification is DISABLED — do not use this in production");
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(null, (chain, authType) -> true)
                    .build();
            SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(
                            PoolingHttpClientConnectionManagerBuilder.create()
                                    .setSSLSocketFactory(sslSocketFactory)
                                    .build())
                    .build();
            factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        } else {
            factory = new HttpComponentsClientHttpRequestFactory();
        }

        factory.setConnectTimeout(props.getConnectTimeout());
        factory.setConnectionRequestTimeout(props.getReadTimeout());

        return new RestTemplate(factory);
    }
}
