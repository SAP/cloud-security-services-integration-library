/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static com.sap.cloud.security.spring.autoconfig.SapSecurityProperties.*;
import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.token.DefaultIdTokenExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenExchangeMode;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.DefaultXsuaaTokenExtension;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * {@link EnableAutoConfiguration} exposes a {@link JwtDecoder}, which has the standard Spring Security Jwt validators
 * as well as the SAP BTP identity provider-specific validators.
 * <p>
 * This Autoconfiguration creates a JwtDecoders with enabled ProofToken check.
 * <p>
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * Can be enabled with property {@code sap.spring.security.identity.prooftoken = true}
 * and {@code sap.spring.security.hybrid.auto = true}.
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@Conditional(Conditions.HybridProofTokenCondition.class)
@EnableConfigurationProperties({ XsuaaServiceConfiguration.class, IdentityServiceConfiguration.class,
		XsuaaServiceConfigurations.class })
public class HybridIdentityServicesProofTokenAutoConfiguration {
	private static final Logger LOGGER = LoggerFactory.getLogger(
			HybridIdentityServicesProofTokenAutoConfiguration.class);

	HybridIdentityServicesProofTokenAutoConfiguration() {
		// no need to create an instance
	}

	@Configuration
	@ConditionalOnMissingBean({ JwtDecoder.class })
	@ConditionalOnWebApplication(type = SERVLET)
	public static class JwtDecoderConfigurations {
		XsuaaServiceConfigurations xsuaaConfigs;

    @Value("${sap.spring.security.hybrid.token.exchange.mode:disabled}")
    private String tokenExchangeMode;

		JwtDecoderConfigurations(XsuaaServiceConfigurations xsuaaConfigs) {
			this.xsuaaConfigs = xsuaaConfigs;
		}

		@Bean
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN)
		public JwtDecoder hybridJwtDecoderProofTokenEnabled(XsuaaServiceConfiguration xsuaaConfig,
				IdentityServiceConfiguration identityConfig,
				ObjectProvider<SecurityCache<String, String>> securityCache) {
			LOGGER.debug("auto-configures HybridJwtDecoder with proofToken check enabled.");
      SecurityCache<String, String> cache = securityCache.getIfAvailable();
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig, cache));
      SecurityContext.registerXsuaaTokenExtension(getDefaultXSUAATokenExtension(xsuaaConfig, cache));
      TokenExchangeMode mode = TokenExchangeMode.fromString(tokenExchangeMode);
      JwtDecoderBuilder builder = new JwtDecoderBuilder()
          .withIasServiceConfiguration(identityConfig)
          .enableProofTokenCheck()
          .withXsuaaServiceConfiguration(xsuaaConfig)
          .withTokenExchange(mode);
      if (cache != null) {
        builder.withSecurityCache(cache);
      }
      return builder.build();
		}

		@Bean
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN)
		public JwtDecoder hybridJwtDecoderMultiXsuaaServicesProofTokenEnabled(
				IdentityServiceConfiguration identityConfig,
				ObjectProvider<SecurityCache<String, String>> securityCache) {
			LOGGER.debug(
					"auto-configures HybridJwtDecoder when bound to multiple xsuaa service instances and proof token check is enabled.");

			List<XsuaaServiceConfiguration> allXsuaaConfigs = xsuaaConfigs.getConfigurations();
			List<XsuaaServiceConfiguration> usedXsuaaConfigs = allXsuaaConfigs.subList(0,
					Math.min(2, allXsuaaConfigs.size()));
			if (usedXsuaaConfigs.size() == 2 && !ServiceConstants.Plan.BROKER.toString()
					.equals(usedXsuaaConfigs.get(1).getProperty(ServiceConstants.SERVICE_PLAN))) {
				usedXsuaaConfigs = usedXsuaaConfigs.subList(0, 1);
			}
      SecurityCache<String, String> cache = securityCache.getIfAvailable();
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig, cache));
      JwtDecoderBuilder builder = new JwtDecoderBuilder()
          .withIasServiceConfiguration(identityConfig)
          .enableProofTokenCheck()
          .withXsuaaServiceConfigurations(usedXsuaaConfigs);
      if (cache != null) {
        builder.withSecurityCache(cache);
      }
      return builder.build();
		}

		@Bean
		@ConditionalOnMissingBean(JwtDecoder.class)
		@ConditionalOnProperty(SAP_SECURITY_SERVICES_IDENTITY_DOMAINS)
		public JwtDecoder iasJwtDecoderProofTokenEnabled(IdentityServiceConfiguration identityConfig,
				ObjectProvider<SecurityCache<String, String>> securityCache) {
			LOGGER.debug("auto-configures iasJwtDecoderWithProofTokenCheck.");
      SecurityCache<String, String> cache = securityCache.getIfAvailable();
      SecurityContext.registerIdTokenExtension(getDefaultIdTokenExtension(identityConfig, cache));
      JwtDecoderBuilder builder = new JwtDecoderBuilder()
          .withIasServiceConfiguration(identityConfig)
          .enableProofTokenCheck();
      if (cache != null) {
        builder.withSecurityCache(cache);
      }
      return builder.build();
		}

	}

  private static DefaultIdTokenExtension getDefaultIdTokenExtension(
      IdentityServiceConfiguration identityConfig,
      SecurityCache<String, String> securityCache) {
    return new DefaultIdTokenExtension(
        new DefaultOAuth2TokenService(
            SecurityHttpClientProvider.createClient(identityConfig.getClientIdentity()),
            TokenCacheConfiguration.defaultConfiguration(),
            securityCache),
        identityConfig);
  }

  private static DefaultXsuaaTokenExtension getDefaultXSUAATokenExtension(
      OAuth2ServiceConfiguration xsuaaConfig,
      SecurityCache<String, String> securityCache) {
    return new DefaultXsuaaTokenExtension(
        new DefaultOAuth2TokenService(
            SecurityHttpClientProvider.createClient(xsuaaConfig.getClientIdentity()),
            TokenCacheConfiguration.defaultConfiguration(),
            securityCache),
        xsuaaConfig);
  }
}
