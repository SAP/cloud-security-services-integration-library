/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock.autoconfiguration;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaMockAutoConfiguration.class}) or
 * with property spring.xsuaa.mock.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "spring.xsuaa.mock", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaMockAutoConfiguration {
	Logger logger = LoggerFactory.getLogger(getClass());

	@Bean
	@Primary
	@ConditionalOnProperty(name = "mockxsuaaserver.url", matchIfMissing = false)
	@ConditionalOnMissingBean(MockXsuaaServiceConfiguration.class)
	public XsuaaServiceConfiguration xsuaaMockServiceConfiguration() {
		logger.info("auto-configure MockXsuaaServiceConfiguration");
		return new MockXsuaaServiceConfiguration();
	}
}
