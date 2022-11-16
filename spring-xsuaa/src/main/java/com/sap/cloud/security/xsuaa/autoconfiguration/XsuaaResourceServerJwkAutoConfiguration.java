/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.springframework.web.client.RestOperations;

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
	@ConditionalOnBean({ XsuaaServiceConfiguration.class, RestOperations.class })
	@ConditionalOnWebApplication(type = Type.SERVLET)
	@ConditionalOnMissingBean
	public JwtDecoder xsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration,
			RestOperations xsuaaRestOperations) {
		logger.debug("auto-configures JwtDecoder using restOperations of type: {}", xsuaaRestOperations);
		return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration)
				.withRestOperations(xsuaaRestOperations)
				.build();
	}
}
