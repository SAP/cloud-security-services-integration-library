/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import com.sap.cloud.security.xsuaa.extractor.TokenUtil;
import com.sap.cloud.security.xsuaa.token.authentication.httpclient.SpringHttpClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nonnull;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for default beans used by
 * the XSUAA client library.
 * <p>
 * Activates when there is a class of type {@link Jwt} on the classpath.
 *
 * <p>
 * can be disabled
 * with @EnableAutoConfiguration(exclude={XsuaaAutoConfiguration.class}) or with
 * property spring.xsuaa.auto = false
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(prefix = "spring.xsuaa", name = "auto", havingValue = "true", matchIfMissing = true)
public class XsuaaAutoConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaAutoConfiguration.class);

	@Configuration
	@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
	@Conditional(PropertyConditions.class)
	public static class XsuaaServiceAutoConfiguration {

		@Bean
		@ConditionalOnMissingBean(XsuaaServiceConfiguration.class)
		public XsuaaServiceConfiguration xsuaaServiceConfiguration() {
			LOGGER.info("auto-configures XsuaaServiceConfigurationDefault");
			return new XsuaaServiceConfigurationDefault();
		}

		@Bean
		public TokenUtil tokenUtil() {
			return new TokenUtil();
		}
	}

	private static class PropertyConditions extends AllNestedConditions {

		public PropertyConditions() {
			super(ConfigurationPhase.PARSE_CONFIGURATION);
		}

		@ConditionalOnProperty(prefix = "spring.xsuaa", name = "multiple-bindings", havingValue = "false", matchIfMissing = true)
		static class MultipleBindingsCondition {
		}

		@ConditionalOnProperty(prefix = "spring.xsuaa", name = "disable-default-property-source", havingValue = "false", matchIfMissing = true)
		static class DisableDefaultPropertySourceCondition {
		}

	}

	/**
	 * Creates a {@link RestOperations} instance if the application has not defined
	 * any.
	 *
	 * @return the {@link RestOperations} instance.
	 */
	@Bean
	@Conditional({ OnSecretCredentialTypeCondition.class, NoClientCertificateCondition.class })
	@ConditionalOnMissingBean
	@ConditionalOnBean(XsuaaServiceConfiguration.class)
	public RestOperations xsuaaRestOperations() {
		LOGGER.warn("In productive environment provide a well configured client secret based RestOperations bean");
		return new RestTemplate();
	}

	/**
	 * Creates a certificate based {@link RestOperations} instance if the
	 * application has not defined any.
	 *
	 * @return the {@link RestOperations} instance.
	 */
	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnClass(name = "org.apache.hc.client5.http.impl.classic.CloseableHttpClient")
	@ConditionalOnBean(XsuaaServiceConfiguration.class)
	public RestOperations xsuaaMtlsRestOperations(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		LOGGER.warn("In productive environment provide a well configured certificate based RestOperations bean");
		return SpringHttpClientFactory.createRestTemplate(xsuaaServiceConfiguration.getClientIdentity());
	}

	private static class OnSecretCredentialTypeCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			CredentialType credentialType = CredentialType
					.from(context.getEnvironment().getProperty("xsuaa.credential-type"));
			return credentialType == CredentialType.BINDING_SECRET || credentialType == CredentialType.INSTANCE_SECRET
					|| credentialType == null;
		}
	}

	private static class NoClientCertificateCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			return context.getEnvironment().getProperty("xsuaa.certificate") == null &&
					context.getEnvironment().getProperty("xsuaa.key") == null;
		}
	}

}