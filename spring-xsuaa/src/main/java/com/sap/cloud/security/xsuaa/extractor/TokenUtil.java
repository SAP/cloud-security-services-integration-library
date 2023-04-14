/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.annotation.PostConstruct;
import java.time.Instant;

/**
 * Token Utility class to determine provided token type i.e. Xsuaa or IAS, check
 * token exchange enablement
 */
public class TokenUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);
	private static final String IAS_XSUAA_ENABLED = "IAS_XSUAA_XCHANGE_ENABLED";
	private static final String EXTERNAL_ATTRIBUTE = "ext_attr";
	private static final String EXTERNAL_ATTRIBUTE_ENHANCER = "enhancer";
	private static String springIasXchangeEnabled;
	@Value("${xsuaa.iasxchange-enabled:#{null}}")
	private String iasXchangeValue;

	@PostConstruct
	public void init() {
		TokenUtil.springIasXchangeEnabled = iasXchangeValue;
	}

	/**
	 * Splits the bearer token into header, payload and signature.
	 * 
	 * @param encodedJwtToken
	 *            encoded jwt token
	 * @return DecodedJwt
	 */
	static DecodedJwt decodeJwt(String encodedJwtToken) {
		return Base64JwtDecoder.getInstance().decode(encodedJwtToken);
	}

	/**
	 * Parses decoded Jwt token to org.springframework.security.oauth2.jwt
	 * 
	 * @param decodedJwt
	 *            decoded Jwt
	 * @return Jwt class
	 */
	static Jwt parseJwt(DecodedJwt decodedJwt) {
		JSONObject payload = new JSONObject(decodedJwt.getPayload());
		JSONObject header = new JSONObject(decodedJwt.getHeader());
		return new Jwt(decodedJwt.getEncodedToken(), Instant.ofEpochSecond(payload.optLong("iat")),
				Instant.ofEpochSecond(payload.getLong("exp")),
				header.toMap(), payload.toMap());
	}

	/**
	 * Determines if the provided decoded jwt token is issued by the XSUAA identity
	 * service.
	 *
	 * @param decodedJwt
	 *            jwt to be checked
	 * @return true if provided token is a XSUAA token
	 */
	static boolean isXsuaaToken(DecodedJwt decodedJwt) {
		String jwtPayload = decodedJwt.getPayload().toLowerCase();
		return jwtPayload.contains(EXTERNAL_ATTRIBUTE)
				&& jwtPayload.contains(EXTERNAL_ATTRIBUTE_ENHANCER)
				&& jwtPayload.contains("xsuaa");
	}

	/**
	 * Checks value of Spring property 'xsuaa.iasxchange-enabled', if it's not
	 * defined it checks value of environment variable 'IAS_XSUAA_XCHANGE_ENABLED'.
	 * This value determines, whether token exchange between IAS and XSUAA is
	 * enabled. If value is not provided or with an empty value or with value =
	 * false, then token exchange is disabled. Any other values are interpreted as
	 * true. Precedence is Spring property source, then System Environment variable.
	 *
	 * @return returns true if exchange is enabled and false if disabled
	 */
	static boolean isIasToXsuaaXchangeEnabled() {
		String isEnabled;
		if (springIasXchangeEnabled == null) {
			isEnabled = System.getenv(IAS_XSUAA_ENABLED);
		} else {
			isEnabled = springIasXchangeEnabled;
		}
		LOGGER.debug("System environment variable {} is set to {}", IAS_XSUAA_ENABLED, isEnabled);
		if (isEnabled != null) {
			return !isEnabled.equalsIgnoreCase("false");
		}
		return false;
	}

}
