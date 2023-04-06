/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
public class XsuaaTokenFlowAutoConfiguration {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	XsuaaServiceConfiguration xsuaaConfig;

	public XsuaaTokenFlowAutoConfiguration(XsuaaServiceConfigurations xsuaaConfigs,
			XsuaaServiceConfiguration xsuaaConfig) {
		logger.debug("prepares XsuaaTokenFlowAutoConfiguration.");
		this.xsuaaConfig = xsuaaConfigs.getConfigurations().isEmpty() ? xsuaaConfig
				: xsuaaConfigs.getConfigurations().get(0);
	}

	@Bean
	@Conditional(PropertyConditions.class)
	public XsuaaTokenFlows xsuaaTokenFlows(@Qualifier("tokenFlowHttpClient") CloseableHttpClient httpClient) {
		logger.debug("auto-configures XsuaaTokenFlows using {} based restOperations",
				xsuaaConfig.getClientIdentity().isCertificateBased() ? "certificate" : "client secret");
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig);
		ClientIdentity clientIdentity = xsuaaConfig.getClientIdentity();
		OAuth2TokenService oAuth2TokenService = new DefaultOAuth2TokenService(httpClient);
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a {@link CloseableHttpClient} instance configured with the
	 * ClientIdentity provided. Conditional on missing CloseableHttpClient Bean.
	 *
	 * @return the {@link CloseableHttpClient} instance.
	 */
	@Bean
	public CloseableHttpClient tokenFlowHttpClient(XsuaaServiceConfiguration xsuaaConfig) {
		logger.info(
				"If the performance for the token validation is degrading provide your own well configured HttpClientFactory implementation");
		return HttpClientFactory.create(xsuaaConfig.getClientIdentity());
	}

	private static class PropertyConditions extends AnyNestedCondition {

		public PropertyConditions() {
			super(ConfigurationPhase.REGISTER_BEAN);
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "xsuaa[0].clientid")
		static class MultipleBindingsCondition {
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "xsuaa.clientid")
		static class SingleBindingCondition {
		}
	}
}
