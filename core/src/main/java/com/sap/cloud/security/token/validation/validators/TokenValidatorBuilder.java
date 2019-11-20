package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.*;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;
import static com.sap.cloud.security.config.cf.CFService.XSUAA;

/**
 * Class used to build a token validator. Custom validators can be added
 * via {@link #with(Validator<Token>)} method.
 */
public class TokenValidatorBuilder {
	private final Collection<Validator<Token>> validators = new ArrayList<>();
	private final OAuth2ServiceConfiguration configuration;
	private OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
	private OAuth2ServiceConfiguration otherConfiguration;
	private Validator<Token> audienceValidator;

	private TokenValidatorBuilder(OAuth2ServiceConfiguration configuration) {
		this.configuration = configuration;
	}

	/**
	 * Creates a {@link TokenValidatorBuilder} object.
	 *
	 * @return the builder.
	 */
	public static TokenValidatorBuilder create() {
		return new TokenValidatorBuilder(null);
	}

	public static TokenValidatorBuilder createFor(OAuth2ServiceConfiguration configuration) {
		return new TokenValidatorBuilder(configuration);
	}

	/**
	 * Add the validator to the validation chain.
	 *
	 * @param validator
	 *            the validator used for validation.
	 * @return this builder.
	 */
	public TokenValidatorBuilder with(Validator<Token> validator) {
		validators.add(validator);
		return this;
	}

	public TokenValidatorBuilder withAudienceValidator(Validator<Token> audienceValidator) {
		this.audienceValidator = audienceValidator;
		return this;
	}

	public TokenValidatorBuilder withOAuth2TokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	public TokenValidatorBuilder configureAnotherServiceInstance(
			@Nullable OAuth2ServiceConfiguration otherConfiguration) {
		this.otherConfiguration = otherConfiguration;
		return this;
	}

	/**
	 * @return the combined validators.
	 */
	public Validator<Token> build() {
		List<Validator<Token>> allValidators = createDefaultValidators();
		allValidators.addAll(validators);
		return new CombiningValidator<>(allValidators);
	}

	private List<Validator<Token>> createDefaultValidators() {
		List<Validator<Token>> defaultValidators = new ArrayList<>();
		defaultValidators.add(new JwtTimestampValidator());
		if (configuration != null && configuration.getServiceName().equalsIgnoreCase(XSUAA.getName())) {
			OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(configuration.getUrl());
			TokenKeyServiceWithCache tokenKeyServiceWithCache = new TokenKeyServiceWithCache(tokenKeyService,
					endpointsProvider);
			XsuaaJwtAudienceValidator audienceValidator = new XsuaaJwtAudienceValidator(
					configuration.getProperty(APP_ID), configuration.getClientId());
			if (otherConfiguration != null) {
				// TODO 20.11.19 c5295400: this audienceValidator is not used
				audienceValidator.configureAnotherServiceInstance(otherConfiguration.getProperty(APP_ID),
						otherConfiguration.getClientId());
			}
			defaultValidators.add(new XsuaaJwtIssuerValidator(configuration.getDomain()));
			defaultValidators.add(new JwtSignatureValidator(tokenKeyServiceWithCache));
			defaultValidators.add(getAudienceValidator(configuration));
		}
		return defaultValidators;
	}

	private Validator<Token> getAudienceValidator(OAuth2ServiceConfiguration configuration) {
		return Optional.ofNullable(audienceValidator)
				.orElse(new XsuaaJwtAudienceValidator(configuration.getProperty(APP_ID), configuration.getClientId()));
	}

}
