package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;

@Configuration
public class HybridAuthorizationAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(XsuaaTokenAuthorizationConverter.class)
    public XsuaaTokenAuthorizationConverter xsuaaAuthConverter(XsuaaServiceConfiguration xsuaaConfig) {
        return new XsuaaTokenAuthorizationConverter(xsuaaConfig.getProperty(APP_ID));
    }
}
