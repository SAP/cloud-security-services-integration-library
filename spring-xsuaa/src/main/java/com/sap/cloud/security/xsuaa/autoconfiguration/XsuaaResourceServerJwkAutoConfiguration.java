package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.*;

/**
 * {@link EnableAutoConfiguration Auto-configuration} that exposes a
 * {@link JwtDecoder}, which has the standard Spring Security Jwt validators as
 * well as the XSUAA-specific validators.
 *
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaResourceServerJwkAutoConfiguration.class})
 * or with property spring.xsuaa.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "spring.xsuaa", name = "auto", havingValue = "true", matchIfMissing = true)
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class) // imports OAuth2ResourceServerJwtConfiguration which
																	// specifies JwtDecoder
public class XsuaaResourceServerJwkAutoConfiguration {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	@Bean
	@ConditionalOnBean(XsuaaServiceConfiguration.class)
	@ConditionalOnWebApplication(type = Type.SERVLET)
	@ConditionalOnMissingBean
	public JwtDecoder xsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		logger.info("auto-configures JwtDecoder");
		return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
	}
}
