/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.client.RestOperations;

import java.util.*;
import java.util.stream.Collectors;

public class XsuaaJwtDecoderBuilder {

	int decoderCacheValidity; // in seconds
	int decoderCacheSize;
	Collection<PostValidationAction> postValidationActions;
	private XsuaaServiceConfiguration configuration;
	private RestOperations restOperations;
	private List<OAuth2TokenValidator<Jwt>> xsuaaTokenValidators;

	/**
	 * Utility for building a JWT decoder configuration
	 *
	 * @param configuration
	 *            of the Xsuaa service
	 */
	public XsuaaJwtDecoderBuilder(XsuaaServiceConfiguration configuration) {
		this.configuration = configuration;
		xsuaaTokenValidators = new ArrayList<>();
		xsuaaTokenValidators.add(new XsuaaAudienceValidator(configuration));
		withDecoderCacheSize(100);
		withDecoderCacheTime(900);
	}

	/**
	 * Assembles a JwtDecoder
	 *
	 * @return JwtDecoder
	 */
	public JwtDecoder build() {
		XsuaaJwtDecoder jwtDecoder = new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize,
				getValidators(), postValidationActions);
		Optional.ofNullable(restOperations).ifPresent(jwtDecoder::setRestOperations);
		return jwtDecoder;
	}

	/**
	 * Assembles a ReactiveJwtDecoder
	 *
	 * @return ReactiveJwtDecoder
	 */
	public ReactiveJwtDecoder buildAsReactive() {
		return new ReactiveXsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize, getValidators(),
				postValidationActions);
	}

	private DelegatingOAuth2TokenValidator<Jwt> getValidators() {
		return new DelegatingOAuth2TokenValidator<>(new DelegatingOAuth2TokenValidator<>(xsuaaTokenValidators),
				JwtValidators.createDefault());
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
	public XsuaaJwtDecoderBuilder withTokenValidators(OAuth2TokenValidator<Jwt>... tokenValidators) {
		xsuaaTokenValidators = Arrays.asList(tokenValidators);
		return this;
	}

	/**
	 * Sets the {@link RestOperations} instance which is used by the JwtDecoder to
	 * perform HTTP requests. This does not effect the {@link ReactiveJwtDecoder}
	 * that is constructed with {@link #buildAsReactive()}
	 *
	 * @param restOperations
	 *            the {@link RestOperations} instance.
	 * @return the builder itself.
	 */
	public XsuaaJwtDecoderBuilder withRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
		return this;
	}

	/**
	 * Disables the JWT {@link XsuaaAudienceValidator} which is enabled by default.
	 *
	 * @return the builder itself.
	 */
	public XsuaaJwtDecoderBuilder withoutXsuaaAudienceValidator() {
		xsuaaTokenValidators = xsuaaTokenValidators.stream()
				.filter(validator -> !(validator instanceof XsuaaAudienceValidator))
				.collect(Collectors.toList());
		return this;
	}

}
