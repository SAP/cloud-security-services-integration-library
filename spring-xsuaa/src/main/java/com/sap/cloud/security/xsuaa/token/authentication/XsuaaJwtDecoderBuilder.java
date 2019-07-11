package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;

public class XsuaaJwtDecoderBuilder {

	private XsuaaServiceConfiguration configuration;
	int decoderCacheValidity; // in seconds
	int decoderCacheSize;
	OAuth2TokenValidator<Jwt> xsuaaTokenValidators;
	OAuth2TokenValidator<Jwt> defaultTokenValidators;
	PostValidationAction postValidationAction;

	/**
	 * Utility for building a JWT decoder configuration
	 *
	 * @param configuration
	 *            of the Xsuaa service
	 */
	public XsuaaJwtDecoderBuilder(XsuaaServiceConfiguration configuration) {
		this.configuration = configuration;
		withDefaultValidators(JwtValidators.createDefault());
		withTokenValidators(new XsuaaAudienceValidator(configuration));
		withDecoderCacheSize(100);
		withDecoderCacheTime(900);
	}

	/**
	 * Assembles a JwtDecoder
	 *
	 * @return JwtDecoder
	 */
	public JwtDecoder build() {
		DelegatingOAuth2TokenValidator<Jwt> combinedTokenValidators = new DelegatingOAuth2TokenValidator<>(
				defaultTokenValidators,
				xsuaaTokenValidators);
		return new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize,
				combinedTokenValidators, postValidationAction);
	}

	/**
	 * Decoders cache the signing keys. Overwrite the cache time (default: 900
	 * seconds).
	 *
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheTime(int timeInSeconds) {
		this.decoderCacheValidity = timeInSeconds;
		return this;
	}

	/**
	 * Overwrite size of cached decoder (default: 100). Mainly relevant for multi
	 * tenant applications.
	 *
	 * @param size
	 *            number of cached decoders
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheSize(int size) {
		this.decoderCacheSize = size;
		return this;
	}

	/**
	 * Sets the PostValidationAction which is executed after successful verification and validation of the token.
	 *
	 * @param postValidationAction
	 *           the PostValidationAction
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withPostValidationAction(PostValidationAction postValidationAction) {
		this.postValidationAction = postValidationAction;
		return this;
	}

	/**
	 * Configures clone token validator, in case of two xsuaa bindings (application
	 * and broker plan).
	 *
	 * @param tokenValidators
	 *            the token validators
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withTokenValidators(OAuth2TokenValidator<Jwt>... tokenValidators) {
		this.xsuaaTokenValidators = new DelegatingOAuth2TokenValidator<>(tokenValidators);
		return this;
	}

	public XsuaaJwtDecoderBuilder withDefaultValidators(OAuth2TokenValidator<Jwt>... defaultTokenValidators) {
		this.defaultTokenValidators = new DelegatingOAuth2TokenValidator<>(defaultTokenValidators);
		return this;
	}
}
