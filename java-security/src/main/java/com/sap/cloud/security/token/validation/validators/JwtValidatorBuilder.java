/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;

/**
 * Class used to build a token validator for an OAuth service configuration
 * {@link OAuth2ServiceConfiguration}. <br>
 * Custom validators can be added via {@link #with(Validator)} method.
 */
public class JwtValidatorBuilder {
	private static final Map<OAuth2ServiceConfiguration, JwtValidatorBuilder> instances = new ConcurrentHashMap<>();
	private final Set<Validator<Token>> validators = new HashSet<>();
	private final Set<ValidationListener> validationListeners = Collections.synchronizedSet(new HashSet<>());
	private OAuth2ServiceConfiguration configuration;
	private final Set<OAuth2ServiceConfiguration> otherConfigurations = Collections.synchronizedSet(new HashSet<>());
	private OidcConfigurationService oidcConfigurationService = null;
	private OAuth2TokenKeyService tokenKeyService = null;
	private Validator<Token> customAudienceValidator;
	private CacheConfiguration tokenKeyCacheConfiguration;
	private boolean isTenantIdCheckDisabled;

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtValidatorBuilder.class);

	private JwtValidatorBuilder() {
		// use getInstance factory method
	}

	/**
	 * Creates a builder instance that can be configured further.
	 *
	 * @param configuration
	 *            the identity service configuration
	 * @return the builder
	 */
	public static JwtValidatorBuilder getInstance(OAuth2ServiceConfiguration configuration) {
		Assertions.assertNotNull(configuration, "configuration must not be null");
		if (instances.containsKey(configuration)) {
			return instances.get(configuration);
		}
		JwtValidatorBuilder instance = new JwtValidatorBuilder();
		instance.configuration = configuration;
		instances.put(configuration, instance);
		return instance;
	}

	/**
	 * Adds a custom validator to the validation chain.
	 *
	 * @param validator
	 *            the validator used for validation.
	 * @return this builder.
	 */
	public JwtValidatorBuilder with(Validator<Token> validator) {
		validators.add(validator);
		return this;
	}

	/**
	 * Use to configure the token key cache.
	 *
	 * @param tokenKeyCacheConfiguration
	 *            the cache configuration
	 * @return this builder
	 */
	public JwtValidatorBuilder withCacheConfiguration(CacheConfiguration tokenKeyCacheConfiguration) {
		this.tokenKeyCacheConfiguration = tokenKeyCacheConfiguration;
		return this;
	}

	/**
	 * Sets / overwrites the default audience validator.
	 *
	 * @param audienceValidator
	 *            the validator used for validation.
	 * @return this builder.
	 */
	public JwtValidatorBuilder withAudienceValidator(Validator<Token> audienceValidator) {
		LOGGER.info("Configures a custom audience validator: {}", audienceValidator.getClass());
		this.customAudienceValidator = audienceValidator;
		return this;
	}

	/**
	 * Overwrite in case you want to configure your own
	 * {@link OAuth2TokenKeyService} instance.
	 *
	 * @param tokenKeyService
	 *            your token key service
	 * @return this builder
	 * @deprecated for internal use only
	 */
	@Deprecated
	public JwtValidatorBuilder withOAuth2TokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Overwrite in case you want to configure your own
	 * {@link OAuth2TokenKeyService} instance.
	 *
	 * @param oidcConfigurationService
	 *            your token key service
	 * @return this builder
	 * @deprecated for internal use only
	 */
	@Deprecated
	public JwtValidatorBuilder withOidcConfigurationService(OidcConfigurationService oidcConfigurationService) {
		this.oidcConfigurationService = oidcConfigurationService;
		return this;
	}

	/**
	 * In case you want to configure the {@link OidcConfigurationService} and the
	 * {@link OAuth2TokenKeyService} with your own Rest client.
	 *
	 * @param httpClient
	 *            your own http client
	 * @return this builder
	 */
	public JwtValidatorBuilder withHttpClient(CloseableHttpClient httpClient) {
		if (httpClient != null) {
			this.oidcConfigurationService = new DefaultOidcConfigurationService(httpClient);
			this.tokenKeyService = new DefaultOAuth2TokenKeyService(httpClient);
		}
		return this;
	}

	/**
	 * Allows to provide another service configuration, e.g. in case you have
	 * multiple Xsuaa identity service instances and you like to accept tokens
	 * issued for them as well.
	 *
	 * @param otherConfiguration
	 *            the configuration of the other service instance, e.g. the broker
	 * @return this builder
	 */
	public JwtValidatorBuilder configureAnotherServiceInstance(
			@Nullable OAuth2ServiceConfiguration otherConfiguration) {
		if (Objects.nonNull(otherConfiguration)) {
			this.otherConfigurations.add(otherConfiguration);
		}
		return this;
	}

	/**
	 * Adds the validation listener to the jwt validator that is being built.
	 *
	 * @param validationListener
	 *            the listener to be added to the validator.
	 * @return this builder
	 */
	public JwtValidatorBuilder withValidatorListener(ValidationListener validationListener) {
		validationListeners.add(validationListener);
		return this;
	}

	/**
	 * Disables tenant id check for JwtSignatureValidator. In case Jwt issuer claim
	 * doesn't match with the url attribute from OAuth2ServiceConfiguration tenant
	 * id (zid) claim needs to be present in token to ensure that the tenant belongs
	 * to this issuer. This method disables the tenant id check. Use with caution as
	 * it relaxes the validation rules! It is not recommended to disable this check
	 * for standard Identity service setup.
	 *
	 * @return this builder
	 */
	public JwtValidatorBuilder disableTenantIdCheck() {
		this.isTenantIdCheckDisabled = true;
		return this;
	}

	/**
	 * Builds the validators with the applied parameters.
	 *
	 * @return the combined validators.
	 */
	public CombiningValidator<Token> build() {
		List<Validator<Token>> allValidators = createDefaultValidators();
		allValidators.addAll(validators);

		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(allValidators);
		validationListeners.forEach(combiningValidator::registerValidationListener);
		return combiningValidator;
	}

	private List<Validator<Token>> createDefaultValidators() {
		List<Validator<Token>> defaultValidators = new ArrayList<>();
		defaultValidators.add(new JwtTimestampValidator());

		if (configuration.getService() == XSUAA) {
			if (!configuration.isLegacyMode()) {
				defaultValidators.add(new XsuaaJkuValidator(configuration.getProperty(UAA_DOMAIN)));
			}
		} else if (configuration.getService() == IAS && configuration.getDomains() != null
				&& !configuration.getDomains().isEmpty()) {
			defaultValidators.add(new JwtIssuerValidator(configuration.getDomains()));
		}
		OAuth2TokenKeyServiceWithCache tokenKeyServiceWithCache = getTokenKeyServiceWithCache();
		Optional.ofNullable(tokenKeyCacheConfiguration).ifPresent(tokenKeyServiceWithCache::withCacheConfiguration);
		JwtSignatureValidator signatureValidator = new JwtSignatureValidator(
				configuration,
				tokenKeyServiceWithCache,
				getOidcConfigurationServiceWithCache());

		if (configuration.getService() == IAS && isTenantIdCheckDisabled) {
			signatureValidator.disableTenantIdCheck();
		}
		defaultValidators.add(signatureValidator);

		Optional.ofNullable(customAudienceValidator).ifPresent(defaultValidators::add);
		if (customAudienceValidator == null) {
			defaultValidators.add(createAudienceValidator());
		}

		return defaultValidators;
	}

	private JwtAudienceValidator createAudienceValidator() {
		JwtAudienceValidator jwtAudienceValidator = new JwtAudienceValidator(configuration.getClientId());
		if (configuration.hasProperty(ServiceConstants.XSUAA.APP_ID)) {
			jwtAudienceValidator.configureTrustedClientId(configuration.getProperty(ServiceConstants.XSUAA.APP_ID));
		}
		otherConfigurations.forEach(otherConfiguration -> {
			jwtAudienceValidator.configureTrustedClientId(otherConfiguration.getClientId());
			if (otherConfiguration.hasProperty(ServiceConstants.XSUAA.APP_ID)) {
				jwtAudienceValidator
						.configureTrustedClientId(otherConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID));
			}
		});
		return jwtAudienceValidator;
	}

	private OAuth2TokenKeyServiceWithCache getTokenKeyServiceWithCache() {
		if (tokenKeyService != null) {
			return OAuth2TokenKeyServiceWithCache.getInstance()
					.withTokenKeyService(tokenKeyService);
		}
		return OAuth2TokenKeyServiceWithCache.getInstance();
	}

	private OidcConfigurationServiceWithCache getOidcConfigurationServiceWithCache() {
		if (oidcConfigurationService != null) {
			return OidcConfigurationServiceWithCache.getInstance()
					.withOidcConfigurationService(oidcConfigurationService);
		}
		return OidcConfigurationServiceWithCache.getInstance();
	}

}
