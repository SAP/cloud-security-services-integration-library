/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import javax.annotation.Nonnull;
import java.util.List;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;

/**
 * {@link EnableAutoConfiguration} exposes a {@link JwtDecoder}, which has the standard Spring Security Jwt validators
 * as well as the SCP identity provider-specific validators.
 * <p>
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * Can be disabled with {@code @EnableAutoConfiguration(exclude={HybridIdentityServicesAutoConfiguration.class})} or
 * with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(name = "sap.spring.security.hybrid.auto", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ XsuaaServiceConfiguration.class, IdentityServiceConfiguration.class,
		XsuaaServiceConfigurations.class })
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class) // imports OAuth2ResourceServerJwtConfiguration which
// specifies JwtDecoder
public class HybridIdentityServicesAutoConfiguration {
	private static final Logger LOGGER = LoggerFactory.getLogger(HybridIdentityServicesAutoConfiguration.class);
	private static final String SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN = "sap.spring.security.identity.prooftoken";
	private static final String SAP_SECURITY_SERVICES_IDENTITY_DOMAINS = "sap.security.services.identity.domains";
	private static final String SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN = "sap.security.services.xsuaa.uaadomain";
	private static final String SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN = "sap.security.services.xsuaa[0].uaadomain";

	HybridIdentityServicesAutoConfiguration() {
		// no need to create an instance
	}

	@Configuration
	@ConditionalOnMissingBean({ JwtDecoder.class })
	@ConditionalOnWebApplication(type = SERVLET)
	public static class JwtDecoderConfigurations {
		XsuaaServiceConfigurations xsuaaConfigs;

		JwtDecoderConfigurations(XsuaaServiceConfigurations xsuaaConfigs) {
			this.xsuaaConfigs = xsuaaConfigs;
		}

		@Bean
		@Conditional(ProofTokenHybridCondition.class)
		public JwtDecoder hybridJwtDecoderWithProofTokenCheck(XsuaaServiceConfiguration xsuaaConfig,
				IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder with proofToken check enabled.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.enableProofTokenCheck()
					.withXsuaaServiceConfiguration(xsuaaConfig)
					.build();
		}

		@Bean
		@ConditionalOnMissingBean(JwtDecoder.class)
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN)
		public JwtDecoder hybridJwtDecoder(XsuaaServiceConfiguration xsuaaConfig,
				IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.withXsuaaServiceConfiguration(xsuaaConfig)
					.build();
		}

		@Bean
		@Conditional(ProofTokenHybridMultiXsuaaCondition.class)
		public JwtDecoder hybridJwtDecoderMultiXsuaaServicesProofTokenEnabled(
				IdentityServiceConfiguration identityConfig) {
			LOGGER.debug(
					"auto-configures HybridJwtDecoder when bound to multiple xsuaa service instances and proof token check is enabled.");

			/*
			 * Use only primary XSUAA config and up to 1 more config of type BROKER to stay
			 * backward-compatible now that XsuaaServiceConfigurations contains all XSUAA
			 * configurations instead of only two.
			 */
			List<XsuaaServiceConfiguration> allXsuaaConfigs = xsuaaConfigs.getConfigurations();
			List<XsuaaServiceConfiguration> usedXsuaaConfigs = allXsuaaConfigs.subList(0,
					Math.min(2, allXsuaaConfigs.size()));
			if (usedXsuaaConfigs.size() == 2 && !ServiceConstants.Plan.BROKER.toString()
					.equals(usedXsuaaConfigs.get(1).getProperty(ServiceConstants.SERVICE_PLAN))) {
				usedXsuaaConfigs = usedXsuaaConfigs.subList(0, 1);
			}

			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.enableProofTokenCheck()
					.withXsuaaServiceConfigurations(usedXsuaaConfigs)
					.build();
		}

		@Bean
		@Primary
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN)
		public JwtDecoder hybridJwtDecoderMultiXsuaaServices(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder when bound to multiple xsuaa service instances.");

			/*
			 * Use only primary XSUAA config and up to 1 more config of type BROKER to stay
			 * backward-compatible now that XsuaaServiceConfigurations contains all XSUAA
			 * configurations instead of only two.
			 */
			List<XsuaaServiceConfiguration> allXsuaaConfigs = xsuaaConfigs.getConfigurations();
			List<XsuaaServiceConfiguration> usedXsuaaConfigs = allXsuaaConfigs.subList(0,
					Math.min(2, allXsuaaConfigs.size()));
			if (usedXsuaaConfigs.size() == 2 && !ServiceConstants.Plan.BROKER.toString()
					.equals(usedXsuaaConfigs.get(1).getProperty(ServiceConstants.SERVICE_PLAN))) {
				usedXsuaaConfigs = usedXsuaaConfigs.subList(0, 1);
			}

			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.withXsuaaServiceConfigurations(usedXsuaaConfigs)
					.build();
		}

		@Bean
		@Conditional(ProofTokenIasCondition.class)
		public JwtDecoder iasJwtDecoderWithProofTokenCheck(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures iasJwtDecoderWithProofTokenCheck.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.enableProofTokenCheck()
					.build();
		}

		@Bean
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_IDENTITY_DOMAINS)
		@ConditionalOnMissingBean(JwtDecoder.class)
		public JwtDecoder iasJwtDecoder(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures IasJwtDecoder.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.build();
		}
	}

	private static class ProofTokenIasCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			Environment env = context.getEnvironment();
			String proofTokenEnabled = env.getProperty(SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN);
			String iasBound = env.getProperty(SAP_SECURITY_SERVICES_IDENTITY_DOMAINS);
			String xsuaaBound = env.getProperty(SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN);
			String xsuaaMultiBound = env.getProperty(SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN);

			return proofTokenEnabled != null && proofTokenEnabled.equals(
					"true") && iasBound != null && !iasBound.isBlank() && xsuaaBound == null && xsuaaMultiBound == null;
		}
	}

	private static class ProofTokenHybridCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			Environment env = context.getEnvironment();
			String proofTokenEnabled = env.getProperty(SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN);
			String xsuaaBound = env.getProperty(SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN);

			return proofTokenEnabled != null && proofTokenEnabled.equals(
					"true") && xsuaaBound != null && !xsuaaBound.isBlank();
		}
	}

	private static class ProofTokenHybridMultiXsuaaCondition implements Condition {
		@Override
		public boolean matches(ConditionContext context, @Nonnull AnnotatedTypeMetadata metadata) {
			Environment env = context.getEnvironment();
			String proofTokenEnabled = env.getProperty(SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN);
			String xsuaaBound = env.getProperty(SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN);

			return proofTokenEnabled != null && proofTokenEnabled.equals(
					"true") && xsuaaBound != null && !xsuaaBound.isBlank();
		}
	}

}
