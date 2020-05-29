package com.sap.cloud.security.cas.spring;

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
