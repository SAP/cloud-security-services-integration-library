package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
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
 * create an instance use the {@link #builder} method. By default the
 * validation stops after one invalid result has been found.
 * 
 * @param <T>
 *            the type to be validated.
 */
public class CombiningValidator<T> implements Validator<T> {

	private final List<Validator<T>> validators;
	private List<String> validationErrors = new ArrayList<>();

	private final boolean stopAfterFirstInvalidResult;

	private CombiningValidator(List<Validator<T>> validators, boolean stopAfterFirstInvalidResult) {
		this.validators = validators;
		this.stopAfterFirstInvalidResult = stopAfterFirstInvalidResult;
	}

	@Override
	public ValidationResult validate(T t) {
		for (Validator<T> validator : validators) {
			ValidationResult result = validator.validate(t);
			if(!result.isValid()) {
				validationErrors.add(result.getErrorDescription());
				if(stopAfterFirstInvalidResult == true) {
					return result;
				}
			}
		}
		if(validationErrors.size() > 0) {
			return createInvalid("{} out of {} validators reported an error. Please see detailed error descriptions.", validationErrors.size(), validators.size());
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

	public List<String> getAllErrorDescriptions() {
		return validationErrors;
	}

	public static class TokenValidatorBuilder {
		private final List<Validator<Token>> validators = new ArrayList<>();
		private boolean stopAfterFirstInvalidResult = true;
		private OAuth2TokenKeyService tokenKeyService = new DefaultOAuth2TokenKeyService();
		private OAuth2ServiceConfiguration configuration;

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

		/**
		 * Causes the created validator to not stop validating after the first invalid
		 * result.
		 * 
		 * @return this builder.
		 */
		public TokenValidatorBuilder validateAll() {
			stopAfterFirstInvalidResult = false;
			return this;
		}

		public TokenValidatorBuilder withOAuth2TokenKeyService(OAuth2TokenKeyService tokenKeyService) {
			this.tokenKeyService = tokenKeyService;
			return this;
		}

		/**
		 * @return the validator.
		 */
		public CombiningValidator<Token> build() {

			if (configuration != null /* && configuration.getServiceName() == "xsuaa"*/) { // TODO
				OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(configuration.getUrl());
				TokenKeyServiceWithCache tokenKeyServiceWithCache = new TokenKeyServiceWithCache(tokenKeyService, endpointsProvider);
				with(new JwtSignatureValidator(tokenKeyServiceWithCache));
				with(new JwtTimestampValidator());
				with(new XsuaaJwtAudienceValidator(configuration.getProperty("appId"), configuration.getClientId()));//TODO
				with(new XsuaaJwtIssuerValidator(configuration.getDomain()));
			}

			return new CombiningValidator(validators, stopAfterFirstInvalidResult);
		}


		void setOAuthConfiguration(OAuth2ServiceConfiguration configuration) {
			this.configuration = configuration;
		}
	}

}
