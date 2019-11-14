package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.*;
import static com.sap.cloud.security.config.cf.CFService.*;

import javax.annotation.Nullable;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import com.sap.cloud.security.config.cf.CFService;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;

import java.util.ArrayList;
import java.util.List;

/**
 * This is a special validator that combines several validators into one. To
 * create an instance use the {@link #builder} method. By default the validation
 * stops after one invalid result has been found.
 * 
 * @param <T>
 *            the type to be validated.
 */
public class CombiningValidator<T> implements Validator<T> {

	private final List<Validator<T>> validators;

	private CombiningValidator(List<Validator<T>> validators) {
		this.validators = validators;
	}

	@Override
	public ValidationResult validate(T t) {
		for (Validator<T> validator : validators) {
			ValidationResult result = validator.validate(t);
			if (result.isErroneous()) {
				return result;
			}
		}
		return ValidationResults.createValid();
	}

	/**
	 * Creates a {@link TokenValidatorBuilder} object.
	 *
	 * @return the builder.
	 */
	public static TokenValidatorBuilder builder() {
		return new TokenValidatorBuilder();
	}

	public static TokenValidatorBuilder builderFor(OAuth2ServiceConfiguration configuration) {
		TokenValidatorBuilder tokenBuilder = builder();
		tokenBuilder.setOAuthConfiguration(configuration);
		return tokenBuilder;
	}

	@Override
	public String toString() {
		StringBuilder validatorNames = new StringBuilder();
		for (Validator<T> v : validators) {
			validatorNames.append(v.getClass().getName()).append(',');
		}
		return validatorNames.toString();
	}

	public static class TokenValidatorBuilder {
		private final List<Validator<Token>> validators = new ArrayList<>();
		private OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
		private OAuth2ServiceConfiguration configuration;
		private OAuth2ServiceConfiguration otherConfiguration;

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

		public TokenValidatorBuilder withOAuth2TokenKeyService(OAuth2TokenKeyService tokenKeyService) {
			this.tokenKeyService = tokenKeyService;
			return this;
		}

		public TokenValidatorBuilder configureAnotherServiceInstance(@Nullable OAuth2ServiceConfiguration otherConfiguration) {
			this.otherConfiguration = otherConfiguration;
			return this;
		}

		/**
		 * @return the combined validators.
		 */
		public CombiningValidator<Token> build() {
			if (configuration != null && configuration.getServiceName().equalsIgnoreCase(XSUAA.getName())) {
				OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(configuration.getUrl());
				TokenKeyServiceWithCache tokenKeyServiceWithCache = new TokenKeyServiceWithCache(tokenKeyService,
						endpointsProvider);
				XsuaaJwtAudienceValidator audienceValidator = new XsuaaJwtAudienceValidator(
						configuration.getProperty(APP_ID), configuration.getClientId());

				audienceValidator.configureAnotherServiceInstance(otherConfiguration.getProperty(APP_ID), otherConfiguration.getClientId());

				with(new JwtTimestampValidator());
				with(new XsuaaJwtIssuerValidator(configuration.getDomain()));
				with(new XsuaaJwtAudienceValidator(configuration.getProperty(APP_ID),
						configuration.getClientId()));
				with(new JwtSignatureValidator(tokenKeyServiceWithCache));
			}

			return new CombiningValidator<>(validators);
		}

		void setOAuthConfiguration(OAuth2ServiceConfiguration configuration) {
			this.configuration = configuration;
		}
	}

}
