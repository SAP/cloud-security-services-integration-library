package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceDefault;
import com.sap.cloud.security.cas.spring.AdcSpringSecurityExpressionHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

    @Value("${OPA_URL:http://localhost:8181}")
    private String adcUrl;

    /**
     * TODO: extract as library: SpringBoot Autoconfiguration
     */
    @Bean
    AdcService adcService() {
        //return new SpringADCService(); // TODO need to support WebClient
        return new AdcServiceDefault(adcUrl);
    }


    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        AdcSpringSecurityExpressionHandler expressionHandler =
                AdcSpringSecurityExpressionHandler.getInstance(adcService());
        return expressionHandler;
    }

}
