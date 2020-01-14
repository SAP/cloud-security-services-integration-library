package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.*;

import javax.annotation.Nullable;
import java.util.*;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.*;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;
import static com.sap.cloud.security.config.Service.XSUAA;

/**
 * Class used to build a token validator for a oauth service configuration
 * {@link OAuth2ServiceConfiguration}. <br>
 * Custom validators can be added via {@link #with(Validator)} method.
 */
public class JwtValidatorBuilder {
	private static Map<OAuth2ServiceConfiguration, JwtValidatorBuilder> instances = new HashMap<>();
	private final Collection<Validator<Token>> validators = new ArrayList<>();
	private OAuth2ServiceConfiguration configuration;
	private OidcConfigurationServiceWithCache oidcConfigurationService = null;
	private OAuth2TokenKeyServiceWithCache tokenKeyService = null;
	private OAuth2ServiceConfiguration otherConfiguration;
	private Validator<Token> customAudienceValidator;

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
	 * Sets / overwrites the default audience validator.
	 *
	 * @param audienceValidator
	 *            the validator used for validation.
	 * @return this builder.
	 */
	public JwtValidatorBuilder withAudienceValidator(Validator<Token> audienceValidator) {
		this.customAudienceValidator = audienceValidator;
		return this;
	}

	/**
	 * Overwrite in case you want to configure your own
	 * {@link OAuth2TokenKeyServiceWithCache}. For example you like to change the
	 * cache settings or you like to configure the {@link OAuth2TokenKeyService}
	 * with your own Rest client.
	 *
	 * @param tokenKeyService
	 *            your token key service
	 * @return this builder
	 */
	public JwtValidatorBuilder withOAuth2TokenKeyService(OAuth2TokenKeyServiceWithCache tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Overwrite in case you want to configure your own
	 * {@link OidcConfigurationServiceWithCache}. For example you like to change the
	 * cache settings or you like to configure the {@link OidcConfigurationService}
	 * with your own Rest client.
	 *
	 * @param oidcConfigurationService
	 *            your token key service
	 * @return this builder
	 */
	public JwtValidatorBuilder withOidcConfigurationService(
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		this.oidcConfigurationService = oidcConfigurationService;
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
		this.otherConfiguration = otherConfiguration;
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

		return new CombiningValidator<>(allValidators);
	}

	private List<Validator<Token>> createDefaultValidators() {
		List<Validator<Token>> defaultValidators = new ArrayList<>();
		defaultValidators.add(new JwtTimestampValidator());
		JwtSignatureValidator signatureValidator = new JwtSignatureValidator(getTokenKeyServiceWithCache(),
				getOidcConfigurationServiceWithCache());
		signatureValidator.withOAuth2Configuration(configuration);
		Optional.ofNullable(customAudienceValidator).ifPresent(defaultValidators::add);
		defaultValidators.add(signatureValidator);

		if (configuration.getService() == XSUAA) {
			if (customAudienceValidator == null) {
				defaultValidators.add(createXsuaaAudienceValidator());
			}
			defaultValidators.add(new XsuaaJwtIssuerValidator(configuration.getProperty(UAA_DOMAIN)));

		} else if (configuration.getService() == IAS) {
			defaultValidators.add(new JwtIssuerValidator(configuration.getDomain()));
		}
		return defaultValidators;
	}

	private XsuaaJwtAudienceValidator createXsuaaAudienceValidator() {
		XsuaaJwtAudienceValidator xsuaaJwtAudienceValidator = new XsuaaJwtAudienceValidator(
				configuration.getProperty(APP_ID), configuration.getClientId());
		if (otherConfiguration != null) {
			xsuaaJwtAudienceValidator.configureAnotherServiceInstance(otherConfiguration.getProperty(APP_ID),
					otherConfiguration.getClientId());
		}
		return xsuaaJwtAudienceValidator;
	}

	private OAuth2TokenKeyServiceWithCache getTokenKeyServiceWithCache() {
		return tokenKeyService != null ? tokenKeyService : OAuth2TokenKeyServiceWithCache.getInstance();
	}

	private OidcConfigurationServiceWithCache getOidcConfigurationServiceWithCache() {
		return oidcConfigurationService != null ? oidcConfigurationService
				: OidcConfigurationServiceWithCache.getInstance();
	}

}
