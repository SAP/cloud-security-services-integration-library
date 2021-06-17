/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link XsuaaTokenFlows} on the
 * classpath.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaTokenFlowAutoConfiguration.class})
 * or with property {@code sap.spring.security.xsuaa.flows.auto = false}.
 */
@Configuration
@ConditionalOnClass(XsuaaTokenFlows.class)
@ConditionalOnProperty(name = "sap.spring.security.xsuaa.flows.auto", havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(HybridIdentityServicesAutoConfiguration.class)
@ConditionalOnMissingBean(XsuaaTokenFlows.class)
class XsuaaTokenFlowAutoConfiguration {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	XsuaaServiceConfiguration xsuaaConfig;

	XsuaaTokenFlowAutoConfiguration(XsuaaServiceConfigurations xsuaaConfigs, XsuaaServiceConfiguration xsuaaConfig) {
		logger.debug("prepares XsuaaTokenFlowAutoConfiguration.");
		this.xsuaaConfig = xsuaaConfigs.getConfigurations().isEmpty() ? xsuaaConfig
				: xsuaaConfigs.getConfigurations().get(0);
	}

	@Bean
	@Conditional(PropertyConditions.class)
	public XsuaaTokenFlows xsuaaTokenFlows() {
		logger.debug("auto-configures XsuaaTokenFlows.");
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig.getUrl());
		ClientIdentity clientIdentity = new ClientCredentials(xsuaaConfig.getClientId(),
				xsuaaConfig.getClientSecret());
		OAuth2TokenService oAuth2TokenService = new DefaultOAuth2TokenService();
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	private static class PropertyConditions extends AnyNestedCondition {

		public PropertyConditions() {
			super(ConfigurationPhase.REGISTER_BEAN);
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "xsuaa[0].clientsecret")
		static class MultipleBindingsCondition {
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "xsuaa.clientsecret")
		static class SingleBindingCondition {
		}
	}
}
