/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER;

/**
 * Creates a {@link Token} instance. Supports Jwt tokens from IAS and XSUAA
 * identity service. TokenFactory loads and instantiates the respective Token
 * dynamically.
 */
public class HybridTokenFactory implements TokenFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(HybridTokenFactory.class);
	private static String xsAppId;
	private static ScopeConverter xsScopeConverter;

	/**
	 * Determines whether the JWT token is issued by XSUAA or IAS identity service,
	 * and creates a Token for it.
	 *
	 * @param jwtToken
	 *            the encoded JWT token (access_token or id_token), e.g. from the
	 *            Authorization Header.
	 * @return the new token instance
	 */
	public Token create(String jwtToken) {
		try {
			Objects.requireNonNull(jwtToken, "Requires encoded jwtToken to create a Token instance.");
			DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(removeBearer(jwtToken));

			if (isXsuaaToken(decodedJwt)) {
				return new XsuaaToken(decodedJwt).withScopeConverter(getOrCreateScopeConverter());
			}
			return new SapIdToken(decodedJwt);
		} catch (JsonParsingException e) {
			throw new JsonParsingException(String.format("Issue with Jwt parsing. Authorization header: %s - %s",
					jwtToken.substring(0, 20), e.getMessage()), e);
		}
	}

	/**
	 * For testing purposes, in case CF Environment is not set.
	 *
	 * @param xsAppId
	 *            the application identifier of your xsuaa service.
	 */
	static void withXsuaaAppId(@Nonnull String xsAppId) {
		LOGGER.debug("XSUAA app id = {}", xsAppId);
		HybridTokenFactory.xsAppId = xsAppId;
		getOrCreateScopeConverter();
	}

	private static ScopeConverter getOrCreateScopeConverter() {
		if (xsScopeConverter == null && getXsAppId() != null) {
			xsScopeConverter = new XsuaaScopeConverter(getXsAppId());
		}
		return xsScopeConverter;
	}

	private static String getXsAppId() {
		if (xsAppId == null) {
			OAuth2ServiceConfiguration serviceConfiguration = Environments.getCurrent().getXsuaaConfiguration();
			if (serviceConfiguration == null) {
				LOGGER.warn("There is no xsuaa service configuration: no local scope check possible.");
			} else {
				xsAppId = serviceConfiguration.getProperty(CFConstants.XSUAA.APP_ID);
			}
		}
		return xsAppId;
	}

	/**
	 * Determines if the provided decoded jwt token is issued by the XSUAA identity
	 * service.
	 *
	 * @param decodedJwt
	 *            jwt to be checked
	 * @return true if provided token is a XSUAA token
	 */
	private static boolean isXsuaaToken(DecodedJwt decodedJwt) {
		String jwtPayload = decodedJwt.getPayload().toLowerCase();
		return (jwtPayload.contains(EXTERNAL_ATTRIBUTE)
				&& jwtPayload.contains(EXTERNAL_ATTRIBUTE_ENHANCER)
				&& jwtPayload.contains("xsuaa"))
				|| jwtPayload.contains("\"zid\":\"uaa\",");
	}

	private static String removeBearer(@Nonnull String jwtToken) {
		Assertions.assertHasText(jwtToken, "jwtToken must not be null / empty");
		Pattern bearerPattern = Pattern.compile("[B|b]earer ");
		return bearerPattern.matcher(jwtToken).replaceFirst("");
	}
}
