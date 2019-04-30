package com.sap.cloud.security.xsuaa.token.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.Token;
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
	OAuth2TokenValidator<Jwt> tokenAudienceValidator;

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
		return new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize, tokenAudienceValidator);
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
	 * Adds audience token validator, in case of two xsuaa bindings (application and broker plan).
	 *
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withCompatibleTokenAudienceValidator(String brokerClientId, String brokerXsAppName) {
		this.tokenAudienceValidator = new XsuaaCompatibilityAudienceValidator(configuration, brokerClientId, brokerXsAppName);
		return this;
	}


	class XsuaaCompatibilityAudienceValidator extends XsuaaAudienceValidator {
		private String brokerClientId;
		private String brokerXsAppName;

		public XsuaaCompatibilityAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration, String brokerClientId, String brokerXsAppName) {
			super(xsuaaServiceConfiguration);
			this.brokerClientId = brokerClientId;
			this.brokerXsAppName = brokerXsAppName;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt token) {
			// case 1 : token issued by own client (or master)
			if (brokerClientId.equals(token.getClaimAsString("client_id"))
					|| (brokerXsAppName.contains("!b")
					&& token.getClaimAsString("client_id").contains("|")
					&& token.getClaimAsString("client_id").endsWith("|" + brokerXsAppName))) {
				return OAuth2TokenValidatorResult.success();
			} else {
				// case 2: foreign token
				List<String> allowedAudiences = getAllowedAudiences(token);
				if (allowedAudiences.contains(xsuaaServiceConfiguration.getAppId())) {
					return OAuth2TokenValidatorResult.success();
				} else {
					return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
							"Missing audience " + xsuaaServiceConfiguration.getAppId(), null));
				}
			}
		}

	}
}
