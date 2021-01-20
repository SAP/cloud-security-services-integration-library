package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.token.authentication.JwtDecoderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;


/**
 * {@link EnableAutoConfiguration Auto-configuration} that exposes a
 * {@link JwtDecoder}, which has the standard Spring Security Jwt validators as
 * well as the SCP identity provider-specific validators.
 *
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={OAuth2ResourceServerAutoConfiguration.class})
 * or with property sap.spring.security.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "sap.spring.security.hybrid.", name = "auto", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({XsuaaServiceConfiguration.class, IdentityServiceConfiguration.class})
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class) // imports OAuth2ResourceServerJwtConfiguration which specifies JwtDecoder
public class HybridIdentityServicesAutoConfiguration { // TODO rename
    private static final Logger LOGGER = LoggerFactory.getLogger(HybridIdentityServicesAutoConfiguration.class);

    @Configuration
    @ConditionalOnMissingBean({JwtDecoder.class})
    @ConditionalOnWebApplication(type = SERVLET)
    static class JwtDecoderConfiguration {
        JwtDecoderConfiguration() {
        }

        @Bean
        public JwtDecoder hybridJwtDecoder(XsuaaServiceConfiguration xsuaaConfig, IdentityServiceConfiguration identityConfig) {
            LOGGER.debug("auto-configures HybridJwtDecoder.");
            return new JwtDecoderBuilder()
                    .withIasServiceConfiguration(identityConfig)
                    .withXsuaaServiceConfiguration(xsuaaConfig)
                    .buildHybrid();
        }
    }


}
