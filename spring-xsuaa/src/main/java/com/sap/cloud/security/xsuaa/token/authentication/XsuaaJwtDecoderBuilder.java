package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.web.client.RestOperations;

public class XsuaaJwtDecoderBuilder {

	private XsuaaServiceConfiguration configuration;
	int decoderCacheValidity; // in seconds
	int decoderCacheSize;
	OAuth2TokenValidator<Jwt> xsuaaTokenValidators;
	OAuth2TokenValidator<Jwt> defaultTokenValidators;
	Collection<PostValidationAction> postValidationActions;
	private RestOperations restOperations;

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
		XsuaaJwtDecoder jwtDecoder = new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize,
				combinedTokenValidators, postValidationActions);
		Optional.ofNullable(restOperations).ifPresent(jwtDecoder::setRestOperations);
		return jwtDecoder;
	}

	/**
	 * Assembles a ReactiveJwtDecoder
	 *
	 * @return ReactiveJwtDecoder
	 */
	public ReactiveJwtDecoder buildAsReactive() {
		DelegatingOAuth2TokenValidator<Jwt> combinedTokenValidators = new DelegatingOAuth2TokenValidator<>(
				defaultTokenValidators,
				xsuaaTokenValidators);
		return new ReactiveXsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize,
				combinedTokenValidators, postValidationActions);
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
	 * Sets the PostValidationActions that are executed after successful
	 * verification and validation of the token.
	 *
	 * @param postValidationActions
	 *            the PostValidationActions
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withPostValidationActions(PostValidationAction... postValidationActions) {
		this.postValidationActions = Arrays.asList(postValidationActions);
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
	// var arg it is only being assigned to a OAuth2TokenValidator<Jwt>[], therefore
	// its type safe.
	@SuppressWarnings("unchecked")
	public XsuaaJwtDecoderBuilder withTokenValidators(OAuth2TokenValidator<Jwt>... tokenValidators) {
		this.xsuaaTokenValidators = new DelegatingOAuth2TokenValidator<>(tokenValidators);
		return this;
	}

	/**
	 * Sets the {@link RestOperations} instance which is used by the JwtDecoder to
	 * perform HTTP requests. This does not effect the {@link ReactiveJwtDecoder}
	 * that is constructed with {@link #buildAsReactive()}
	 *
	 * @param restOperations
	 *            the {@code RestOperations} instance.
	 * @return the builder itself.
	 */
	public XsuaaJwtDecoderBuilder withRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
		return this;
	}

	XsuaaJwtDecoderBuilder withDefaultValidators(OAuth2TokenValidator<Jwt>... defaultTokenValidators) {
		this.defaultTokenValidators = new DelegatingOAuth2TokenValidator<>(defaultTokenValidators);
		return this;
	}

}
