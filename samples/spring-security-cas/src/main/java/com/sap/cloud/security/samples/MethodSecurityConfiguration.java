package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.cas.client.AdcServiceDefault;
import com.sap.cloud.security.cas.spring.AdcSpringSecurityExpressionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

    @Autowired
    AdcService adcService;

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        AdcSpringSecurityExpressionHandler expressionHandler =
                AdcSpringSecurityExpressionHandler.getInstance(adcService);
        return expressionHandler;
    }

}
