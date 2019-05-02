package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.List;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

public class XsuaaJwtDecoderBuilder {

	private XsuaaServiceConfiguration configuration;
	int decoderCacheValidity = 900;
	int decoderCacheSize = 100;
	OAuth2TokenValidator<Jwt> cloneTokenValidator;

	/**
	 * Utility for building a JWT decoder configuration
	 *
	 * @param configuration
	 *            of the Xsuaa service
	 */
	public XsuaaJwtDecoderBuilder(XsuaaServiceConfiguration configuration) {
		this.configuration = configuration;
	}

	/**
	 * Assembles a JwtDecoder
	 *
	 * @return JwtDecoder
	 */
	public JwtDecoder build() {
		return new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize, cloneTokenValidator);
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
	 * Configures clone token validator, in case of two xsuaa bindings (application and broker plan).
	 *
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withCompatibleTokenAudienceValidator(String brokerClientId, String brokerXsAppName) {
		this.cloneTokenValidator = new XsuaaCloneTokenValidator(brokerClientId, brokerXsAppName);
		return this;
	}

}
