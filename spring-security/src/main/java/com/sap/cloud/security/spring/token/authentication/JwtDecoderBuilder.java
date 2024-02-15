/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Builder that creates a {@link JwtDecoder} that can handle both kind of
 * tokens:
 * <ul>
 * <li>access tokens from Xsuaa service instance</li>
 * <li>oidc tokens from Identity service instance.</li>
 * </ul>
 */
public class JwtDecoderBuilder {
	private List<? extends OAuth2ServiceConfiguration> xsuaaConfigurations;
	private OAuth2ServiceConfiguration iasConfiguration;
	private final List<ValidationListener> validationListeners = new ArrayList<>();
	protected CloseableHttpClient httpClient;
	private CacheConfiguration tokenKeyCacheConfiguration;

	/**
	 * Use to configure the token key cache.
	 *
	 * @param cacheConfiguration
	 *            the cache configuration
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.tokenKeyCacheConfiguration = cacheConfiguration;
		return this;
	}

	/**
	 * Use to configure the HttpClient that is used to retrieve token keys.
	 *
	 * @param httpClient
	 *            the HttpClient
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withHttpClient(CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
		return this;
	}

	/**
	 * Adds the validation listener to the jwt validator that is being used by the
	 * authenticator to validate the tokens.
	 *
	 * @param validationListener
	 *            the listener to be added.
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withValidationListener(ValidationListener validationListener) {
		this.validationListeners.add(validationListener);
		return this;
	}

	/**
	 * Use to override the ias service configuration used.
	 *
	 * @param serviceConfiguration
	 *            the ias service configuration to use
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withIasServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		this.iasConfiguration = serviceConfiguration;
		return this;
	}

	/**
	 * Use to override the xsuaa service configuration used.
	 *
	 * @param serviceConfiguration
	 *            the xsuaa service configuration to use
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withXsuaaServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		this.xsuaaConfigurations = Collections.singletonList(serviceConfiguration);
		return this;
	}

	/**
	 * Allows to provide multiple xsuaa service configuration. In case you have
	 * multiple Xsuaa identity service instances and you like to accept tokens
	 * issued for them as well. The configuration of the the first one (index 0) is
	 * taken as main configuration.
	 *
	 * @param serviceConfigurations
	 *            all configurations of the xsuaa service instance, e.g. the broker
	 * @return this jwt decoder builder
	 */
	public JwtDecoderBuilder withXsuaaServiceConfigurations(
			List<? extends OAuth2ServiceConfiguration> serviceConfigurations) {
		Assert.notEmpty(serviceConfigurations,
				"serviceConfigurations must not be empty. Expect at least one xsuaa service configuration.");
		this.xsuaaConfigurations = serviceConfigurations;
		return this;
	}

	/**
	 * Assembles a JwtDecoder
	 *
	 * @return JwtDecoder
	 */
	public JwtDecoder build() {
		CombiningValidator<Token> xsuaaValidator = getValidators(Service.XSUAA);
		CombiningValidator<Token> iasValidator = getValidators(Service.IAS);
		if (xsuaaConfigurations != null && !xsuaaConfigurations.isEmpty()) {
			return new HybridJwtDecoder(xsuaaValidator, iasValidator);
		}

		if (iasValidator == null) {
			throw new IllegalStateException("There is no xsuaa and no identity service config.");
		}
		return new IasJwtDecoder(iasValidator);// lgtm[java/dereferenced-value-may-be-null]-line127
	}

	private JwtValidatorBuilder initializeBuilder(OAuth2ServiceConfiguration config) {
		JwtValidatorBuilder builder = JwtValidatorBuilder.getInstance(config)
				.withCacheConfiguration(tokenKeyCacheConfiguration)
				.withHttpClient(httpClient);
		for (ValidationListener listener : validationListeners) {
			builder.withValidatorListener(listener);
		}
		return builder;
	}

	public ReactiveHybridJwtDecoder buildAsReactive() {
		CombiningValidator<Token> xsuaaValidator = getValidators(Service.XSUAA);
		CombiningValidator<Token> iasValidator = getValidators(Service.IAS);
		if (xsuaaConfigurations != null && !xsuaaConfigurations.isEmpty()) {
			return new ReactiveHybridJwtDecoder(xsuaaValidator, iasValidator);
		}
		return null;
	}

	private CombiningValidator<Token> getValidators(Service name) {
		if (name == Service.XSUAA && xsuaaConfigurations != null && !xsuaaConfigurations.isEmpty()) {
			int index = 0;
			JwtValidatorBuilder xsuaaValidatorBuilder = initializeBuilder(xsuaaConfigurations.get(index));
			for (OAuth2ServiceConfiguration xsuaaConfig : xsuaaConfigurations) {
				if (index++ != 0) {
					xsuaaValidatorBuilder.configureAnotherServiceInstance(xsuaaConfig);
				}
			}
			return xsuaaValidatorBuilder.build();
		}
		if (name == Service.IAS) {
			if (iasConfiguration != null && !iasConfiguration.getProperties().isEmpty()) {
				JwtValidatorBuilder iasValidatorBuilder = initializeBuilder(iasConfiguration);
				return iasValidatorBuilder.build();
			}
		}
		return null;
	}
}
