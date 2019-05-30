package com.sap.cloud.security.xsuaa.autoconfiguration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.tokenflows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.TokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

/**
 * Auto-configuration of default beans used by the 
 * XSUAA client library.
 */
@Configuration
@ConditionalOnClass(Jwt.class)
public class XsuaaDefaultConfigurations {

    @Bean
    @ConditionalOnMissingBean
    public XsuaaTokenFlows xsuaaTokenFlows(RestTemplate restTemplate, TokenDecoder decoder) {
        return new XsuaaTokenFlows(restTemplate, decoder);
    }
    
    /**
     * Creates a {@link TokenDecoder} instance 
     * based on a {@link NimbusJwtDecoderJwkSupport} 
     * implementation. 
     * @return the {@link TokenDecoder} instance.
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenDecoder xsuaaTokenDecoder() {
        return new NimbusTokenDecoder();
    }
    
    /**
     * Creates a {@link RestTemplate} instance 
     * if the application has not yet defined any 
     * yet.
     * @return the {@link RestTemplate} instance.
     */
    @Bean
    @ConditionalOnMissingBean
    public RestTemplate xsuaaTokenFlowRestTemplate() {
        return new RestTemplate();
    }
}
