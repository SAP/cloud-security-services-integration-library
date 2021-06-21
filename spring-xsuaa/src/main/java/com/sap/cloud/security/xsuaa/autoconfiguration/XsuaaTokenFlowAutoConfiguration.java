/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.client.ServiceClientException;
import com.sap.cloud.security.xsuaa.mtls.SpringHttpClient;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import com.sap.cloud.security.config.ClientIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
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
 * or with property spring.xsuaa.flows.auto = false
 */
@Configuration
@ConditionalOnClass(XsuaaTokenFlows.class)
@ConditionalOnProperty(prefix = "spring.xsuaa.flows", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaTokenFlowAutoConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(XsuaaTokenFlowAutoConfiguration.class);

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that applications can auto-wire
	 * into their controllers to perform a programmatic token flow exchange.
	 *
	 * @param xsuaaRestOperations
	 *            - the {@link RestOperations} to use for the token flow exchange.
	 * @param xsuaaServiceConfiguration
	 *            - the {@link XsuaaServiceConfiguration} to configure the Xsuaa
	 *            Base Url.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnBean({ XsuaaServiceConfiguration.class, RestOperations.class })
	@Conditional(OnNotX509CredentialTypeCondition.class)
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaTokenFlows(RestOperations xsuaaRestOperations,
			XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		logger.debug("auto-configures XsuaaTokenFlows using restOperations of type: {}", xsuaaRestOperations);
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				xsuaaServiceConfiguration);
		ClientIdentity clientCredentials = xsuaaServiceConfiguration.getClientIdentity();
		OAuth2TokenService oAuth2TokenService = new XsuaaOAuth2TokenService(xsuaaRestOperations);
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientCredentials);
	}

	/**
	 * Creates a new {@link XsuaaTokenFlows} bean that supports mTLS that
	 * applications can auto-wire into their controllers to perform a programmatic
	 * token flow exchange.
	 *
	 * - the {@link RestOperations} to use for the token flow exchange.
	 * 
	 * @param xsuaaServiceConfiguration
	 *            - the {@link XsuaaServiceConfiguration} to configure the Xsuaa
	 *            Base Url.
	 * @return the {@link XsuaaTokenFlows} API.
	 */
	@Bean
	@ConditionalOnBean({ XsuaaServiceConfiguration.class, RestOperations.class })
	@ConditionalOnProperty(prefix = "xsuaa", name = "credential-type", havingValue = "x509")
	@ConditionalOnMissingBean
	public XsuaaTokenFlows xsuaaMtlsTokenFlows(
			XsuaaServiceConfiguration xsuaaServiceConfiguration) throws ServiceClientException {
		logger.debug("auto-configures XsuaaTokenFlows using mTLS restOperations with uaacert endpoint: {}",
				xsuaaServiceConfiguration.getCertUrl());
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				xsuaaServiceConfiguration);
		ClientIdentity clientCertificate = xsuaaServiceConfiguration.getClientIdentity();
		OAuth2TokenService oAuth2TokenService = new XsuaaOAuth2TokenService(SpringHttpClient.getInstance().create(clientCertificate));
		return new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, clientCertificate);
	}

	private static class OnNotX509CredentialTypeCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			CredentialType credentialType = CredentialType
					.from(context.getEnvironment().getProperty("xsuaa.credential-type"));
			return credentialType == CredentialType.BINDING_SECRET || credentialType == CredentialType.INSTANCE_SECRET
					|| credentialType == null;
		}
	}
}
