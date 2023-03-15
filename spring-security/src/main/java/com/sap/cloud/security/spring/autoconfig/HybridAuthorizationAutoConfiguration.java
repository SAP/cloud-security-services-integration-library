/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
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

import static com.sap.cloud.security.config.cf.ServiceConstants.XSUAA.APP_ID;

/**
 * {@link EnableAutoConfiguration} exposes a {@link JwtDecoder}, which is able
 * to decode and validate tokens from Xsuaa and Identity service.
 *
 * <p>
 * Can be disabled with
 * {@code @EnableAutoConfiguration(exclude={HybridIdentityServicesAutoConfiguration.class})}
 * or with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnProperty(name = "sap.spring.security.hybrid.auto", havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(HybridIdentityServicesAutoConfiguration.class)
public class HybridAuthorizationAutoConfiguration {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	@Bean
	@ConditionalOnMissingBean(XsuaaTokenAuthorizationConverter.class)
	@ConditionalOnProperty("sap.security.services.xsuaa.xsappname")
	public Converter<Jwt, AbstractAuthenticationToken> xsuaaAuthConverter(XsuaaServiceConfiguration xsuaaConfig) {
		logger.debug(
				"auto-configures Converter<Jwt, AbstractAuthenticationToken> with 'xsuaa.xsappname' from XsuaaServiceConfiguration.");
		return new XsuaaTokenAuthorizationConverter(xsuaaConfig.getProperty(APP_ID));
	}
}
