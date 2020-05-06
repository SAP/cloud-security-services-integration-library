package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.ADCService;
import com.sap.cloud.security.cas.client.DefaultADCService;
import com.sap.cloud.security.cas.spring.ADCSpringSecurityExpressionHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.net.URI;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

    @Value("${OPA_URL:http://localhost:8181}")
    private String adcUrl;

    /**
     * TODO: extract as library: SpringBoot Autoconfiguration
     */
    @Bean
    ADCService adcService() {
        //return new SpringADCService(); // TODO need to support WebClient
        return new DefaultADCService();
    }

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        ADCSpringSecurityExpressionHandler expressionHandler =
                ADCSpringSecurityExpressionHandler.getInstance(adcService(), URI.create(adcUrl));
        return expressionHandler;
    }

}
