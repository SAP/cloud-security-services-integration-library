package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;

@Configuration
@AutoConfigureAfter(HybridIdentityServicesAutoConfiguration.class)
class HybridAuthorizationAutoConfiguration {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Bean
    @ConditionalOnMissingBean(XsuaaTokenAuthorizationConverter.class)
    public XsuaaTokenAuthorizationConverter xsuaaAuthConverter(XsuaaServiceConfiguration xsuaaConfig) {
        logger.debug("auto-configures Converter<Jwt, AbstractAuthenticationToken> with 'xsuaa.xsappname' from XsuaaServiceConfiguration.");
        return new XsuaaTokenAuthorizationConverter(xsuaaConfig.getProperty(APP_ID));
    }
}
