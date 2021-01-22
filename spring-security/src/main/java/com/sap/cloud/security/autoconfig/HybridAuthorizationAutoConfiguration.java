package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;

/**
 * {@link EnableAutoConfiguration} exposes a
 * {@link JwtDecoder}, which is able to decode and validate tokens from Xsuaa and Identity service.
 *
 * <p>
 * Can be disabled
 * with {@code @EnableAutoConfiguration(exclude={HybridAuthorizationAutoConfiguration.class})}
 * or with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnProperty(prefix = "sap.spring.security.hybrid.", name = "auto", havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(HybridIdentityServicesAutoConfiguration.class)
class HybridAuthorizationAutoConfiguration {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Bean
    @ConditionalOnMissingBean(XsuaaTokenAuthorizationConverter.class)
    public Converter<Jwt, AbstractAuthenticationToken> xsuaaAuthConverter(XsuaaServiceConfiguration xsuaaConfig) {
        logger.debug("auto-configures Converter<Jwt, AbstractAuthenticationToken> with 'xsuaa.xsappname' from XsuaaServiceConfiguration.");
        return new XsuaaTokenAuthorizationConverter(xsuaaConfig.getProperty(APP_ID));
    }
}
