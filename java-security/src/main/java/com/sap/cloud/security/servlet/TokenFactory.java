package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER;

/**
 * Creates a {@link Token} instance. Supports Jwt tokens from IAS and XSUAA
 * identity service. This will be moved to java-api component soon and will load
 * and instantiate the respective Token dynamically.
 */
class TokenFactory {

	private TokenFactory() {
		// use the factory method instead
	}

	/**
	 * Determines whether the JWT token is issued by XSUAA identity service, and
	 * creates a Token for it.
	 *
	 * @param jwtToken
	 *            the encoded JWT token (access_token or id_token), e.g. from the
	 *            Authorization Header.
	 * @return the new token instance
	 */
	public static Token create(String jwtToken) {
		return create(jwtToken, null);
	}

	/**
	 * Determines whether the JWT token is issued by XSUAA identity service, and
	 * creates a Token for it.
	 *
	 * @param jwtToken
	 *            the encoded JWT token (access_token or id_token), e.g. from the
	 *            Authorization Header.
	 * @param localScopeConverter
	 *            the scope converter, e.g. {@link XsuaaScopeConverter}
	 * @return the new token instance
	 */
	public static Token create(String jwtToken, ScopeConverter localScopeConverter) {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(removeBearer(jwtToken));

		if (isXsuaaToken(decodedJwt)) {
			return new XsuaaToken(decodedJwt).withScopeConverter(localScopeConverter);
		}
		return new SapIdToken(decodedJwt);
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
		return jwtPayload.contains(EXTERNAL_ATTRIBUTE)
				&& jwtPayload.contains(EXTERNAL_ATTRIBUTE_ENHANCER)
				&& jwtPayload.contains("xsuaa");
	}

	private static String removeBearer(@Nonnull String jwtToken) {
		Assertions.assertHasText(jwtToken, "jwtToken must not be null / empty");
		Pattern bearerPattern = Pattern.compile("[B|b]earer ");
		return bearerPattern.matcher(jwtToken).replaceFirst("");
	}
}
