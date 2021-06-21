/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.mtls.ServiceClientException;
import com.sap.cloud.security.xsuaa.mtls.SpringHttpClient;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.web.client.RestOperations;

import javax.annotation.Nonnull;

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
	@Conditional({OnNotX509CredentialTypeCondition.class, PropertyConditions.class})
	public XsuaaTokenFlows xsuaaTokenFlows() {
		logger.debug("auto-configures XsuaaTokenFlows.");
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig);
		ClientIdentity clientIdentity = xsuaaConfig.getClientIdentity();
		OAuth2TokenService oAuth2TokenService = new DefaultOAuth2TokenService();
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that supports mTLS that
	 * applications can auto-wire into their controllers to perform a programmatic
	 * token flow exchange.
	 *
	 * - the {@link RestOperations} to use for the token flow exchange.
	 *
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnProperty(prefix = "sap.security.services.xsuaa", name = "credential-type", havingValue = "x509")
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaMtlsTokenFlows() throws ServiceClientException {
		logger.debug("auto-configures XsuaaTokenFlows using mTLS restOperations with uaacert endpoint: {}",
				xsuaaConfig.getCertUrl());
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig);
		ClientIdentity clientCertificate = xsuaaConfig.getClientIdentity();
		OAuth2TokenService oAuth2TokenService = new XsuaaOAuth2TokenService(SpringHttpClient.getInstance().create(clientCertificate));
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientCertificate);
	}

	private static class OnNotX509CredentialTypeCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			CredentialType credentialType = CredentialType
					.from(context.getEnvironment().getProperty("sap.security.services.xsuaa.credential-type"));
			return credentialType == CredentialType.BINDING_SECRET || credentialType == CredentialType.INSTANCE_SECRET
					|| credentialType == null;
		}
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
