/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static com.sap.cloud.security.spring.autoconfig.SapSecurityProperties.*;
import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * {@link EnableAutoConfiguration} exposes a {@link JwtDecoder}, which has the standard Spring Security Jwt validators
 * as well as the SAP BTP identity provider-specific validators.
 * <p>
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * Can be disabled with {@code @EnableAutoConfiguration(exclude={HybridIdentityServicesAutoConfiguration.class})} or
 * with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@Conditional(Conditions.HybridDefaultCondition.class)
@EnableConfigurationProperties({ XsuaaServiceConfiguration.class, IdentityServiceConfiguration.class,
		XsuaaServiceConfigurations.class })
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class) // imports OAuth2ResourceServerJwtConfiguration which
// specifies JwtDecoder
public class HybridIdentityServicesAutoConfiguration {
	private static final Logger LOGGER = LoggerFactory.getLogger(HybridIdentityServicesAutoConfiguration.class);

	HybridIdentityServicesAutoConfiguration() {
		// no need to create an instance
	}

	@Configuration
	@ConditionalOnMissingBean({ JwtDecoder.class })
	@ConditionalOnWebApplication(type = SERVLET)
	public static class JwtDecoderConfigurations {
		XsuaaServiceConfigurations xsuaaConfigs;

    @Value("${sap.spring.security.hybrid.authentication.token.exchange:false}")
    private boolean enableTokenExchange;

		JwtDecoderConfigurations(XsuaaServiceConfigurations xsuaaConfigs) {
			this.xsuaaConfigs = xsuaaConfigs;
		}


		@Bean
		@ConditionalOnMissingBean(JwtDecoder.class)
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN)
		public JwtDecoder hybridJwtDecoder(XsuaaServiceConfiguration xsuaaConfig,
				IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder.");
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig));
      return new JwtDecoderBuilder()
          .withIasServiceConfiguration(identityConfig)
          .withXsuaaServiceConfiguration(xsuaaConfig)
          .withTokenExchange(enableTokenExchange)
          .build();
		}


		@Bean
		@Primary
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN)
		public JwtDecoder hybridJwtDecoderMultiXsuaaServices(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder when bound to multiple xsuaa service instances.");
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig));
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
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_IDENTITY_DOMAINS)
		@ConditionalOnMissingBean(JwtDecoder.class)
		public JwtDecoder iasJwtDecoder(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures IasJwtDecoder.");
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig));
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.build();
		}
	}

  private static DefaultIdTokenExtension getDefaultIdTokenExtension(
      IdentityServiceConfiguration identityConfig) {
    return new DefaultIdTokenExtension(
        new DefaultOAuth2TokenService(HttpClientFactory.create(identityConfig.getClientIdentity())),
        identityConfig);
  }
}
