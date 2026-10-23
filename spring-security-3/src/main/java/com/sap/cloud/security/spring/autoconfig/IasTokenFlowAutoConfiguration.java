/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration;
import com.sap.cloud.security.ias.tokenflows.IasTokenFlows;
import com.sap.cloud.security.spring.config.IasServiceConfiguration;
import com.sap.cloud.security.spring.config.IasServiceConfigurations;
import com.sap.cloud.security.spring.config.IasTenantHostCacheProperties;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for the IAS token flows.
 * <p>
 * Activates when an IAS service binding is present (property
 * {@code sap.security.services.ias.clientid} or {@code sap.security.services.ias[0].clientid}) and
 * {@link IasTokenFlows} is on the classpath.
 * <p>
 * The IAS tenant host resolver is created automatically when the IAS service binding carries the
 * {@code btp-tenant-api} property; the resolver cache is configured via
 * {@code sap.spring.security.ias.tenant-host-cache.*} and, if a
 * {@link SecurityCache} bean is present (see {@code sap.security.cache.distributed.enabled}),
 * shared with the token caches.
 *
 * <p>
 * Can be disabled with {@code @EnableAutoConfiguration(exclude={IasTokenFlowAutoConfiguration.class})}
 * or with property {@code sap.spring.security.ias.flows.auto = false}.
 */
@Configuration
@ConditionalOnClass(IasTokenFlows.class)
@ConditionalOnProperty(name = "sap.spring.security.ias.flows.auto", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ IasServiceConfiguration.class, IasServiceConfigurations.class,
		IasTenantHostCacheProperties.class })
@AutoConfigureAfter(SecurityCacheAutoConfiguration.class)
public class IasTokenFlowAutoConfiguration {
	private static final Logger logger = LoggerFactory.getLogger(IasTokenFlowAutoConfiguration.class);

	@Bean
	@ConditionalOnMissingBean
	@Conditional(IasBindingConditions.class)
	public IasTokenFlows iasTokenFlows(
			final IasServiceConfigurations iasConfigs,
			final IasServiceConfiguration iasConfig,
			@Qualifier("iasTokenFlowHttpClient") final SecurityHttpClient httpClient,
			final ObjectProvider<SecurityCache<String, String>> securityCache,
			final IasTenantHostCacheConfiguration iasTenantHostCacheConfiguration) {
		final OAuth2ServiceConfiguration config = firstIasConfiguration(iasConfigs, iasConfig);
		logger.debug("auto-configuring IasTokenFlows using {} based restOperations",
				iasConfig.getClientIdentity() != null && iasConfig.getClientIdentity().isCertificateBased()
						? "certificate"
						: "client secret");
		final SecurityCache<String, String> cache = securityCache.getIfAvailable();
		final OAuth2TokenService tokenService = new DefaultOAuth2TokenService(
				httpClient, TokenCacheConfiguration.defaultConfiguration(), cache);
		return IasTokenFlows.fromConfiguration(tokenService, config, iasTenantHostCacheConfiguration, cache);
	}

	@Bean
	@ConditionalOnMissingBean
	@Conditional(IasBindingConditions.class)
	public IasTenantHostCacheConfiguration iasTenantHostCacheConfiguration(
			final IasTenantHostCacheProperties properties) {
		return IasTenantHostCacheConfiguration.builder()
				.enabled(properties.isEnabled())
				.ttl(properties.getTtl())
				.maxSize(properties.getMaxSize())
				.localInformationOnly(properties.isLocalInformationOnly())
				.build();
	}

	/**
	 * Creates a {@link SecurityHttpClient} instance configured with the IAS ClientIdentity.
	 * Uses Java HttpClient by default, but Apache HttpClient will be used if token-client-apache
	 * is on the classpath.
	 *
	 * @return the {@link SecurityHttpClient} instance.
	 * @throws HttpClientException if the client cannot be created
	 */
	@Bean(name = "iasTokenFlowHttpClient")
	@Conditional(IasBindingConditions.class)
	public SecurityHttpClient iasTokenFlowHttpClient(
			final IasServiceConfigurations iasConfigs,
			final IasServiceConfiguration iasConfig) throws HttpClientException {
		logger.debug("Auto-configuring IAS SecurityHttpClient. Apache HttpClient will be used if"
				+ " token-client-apache is on classpath.");
		return SecurityHttpClientProvider.createClient(
				firstIasConfiguration(iasConfigs, iasConfig).getClientIdentity());
	}

	private static OAuth2ServiceConfiguration firstIasConfiguration(
			final IasServiceConfigurations iasConfigs,
			final IasServiceConfiguration iasConfig) {
		return iasConfigs.getConfigurations().isEmpty()
				? iasConfig
				: iasConfigs.getConfigurations().get(0);
	}

	private static class IasBindingConditions extends AnyNestedCondition {

		public IasBindingConditions() {
			super(ConfigurationPhase.REGISTER_BEAN);
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "ias[0].clientid")
		static class MultipleBindingsCondition {
		}

		@ConditionalOnProperty(prefix = "sap.security.services", name = "ias.clientid")
		static class SingleBindingCondition {
		}
	}
}
