package com.sap.cloud.security.cas.spring;

import com.sap.cloud.security.cas.client.DefaultAdcService;
import com.sap.cloud.security.cas.client.api.AdcService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * TODO
 *  - check whether it works on CF (can load OPA_URL) timely
 *  - check whether we can expose AdcService as Spring Service.
 */
/*@Configuration
public class AdcConfiguration {

    @Value("${OPA_URL:http://localhost:8181}")
    private String adcUrl;

    @Bean
    AdcService adcService() {
        return new DefaultAdcService(adcUrl);
    }
}*/
