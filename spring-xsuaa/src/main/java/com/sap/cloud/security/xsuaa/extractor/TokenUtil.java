package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token Utility class to determine provided token type i.e. Xsuaa or IAS, check token exchange enablement
 */
class TokenUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);
	private static final String IAS_XSUAA_ENABLED = "IAS_XSUAA_XCHANGE_ENABLED";
	private static final String EXTERNAL_ATTRIBUTE = "ext_attr";
	private static final String EXTERNAL_ATTRIBUTE_ENHANCER = "enhancer";
	private TokenUtil() {
		// use the factory method instead
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
	 * Determines if the provided decoded jwt token is issued by the XSUAA identity
	 * service.
	 * @param encodedJwtToken
	 *            Encoded token to be checked
	 * @return true if provided token is a XSUAA token
	 */
	static boolean isXsuaaToken(String encodedJwtToken) {
		DecodedJwt jwtPayload = Base64JwtDecoder.getInstance().decode(encodedJwtToken);
		return isXsuaaToken(jwtPayload);
	}

	/**
	 * Checks value of environment variable 'IAS_XSUAA_XCHANGE_ENABLED'. This value
	 * determines, whether token exchange between IAS and XSUAA is enabled. If
	 * IAS_XSUAA_XCHANGE_ENABLED is not provided or with an empty value or with
	 * value = false, then token exchange is disabled. Any other values are
	 * interpreted as true.
	 *
	 * @return returns true if exchange is enabled and false if disabled
	 */
	static boolean isIasToXsuaaXchangeEnabled() {
		String isEnabled = System.getenv(IAS_XSUAA_ENABLED);
		LOGGER.debug("System environment variable {} is set to {}", IAS_XSUAA_ENABLED, isEnabled);
		if (isEnabled != null) {
			return !isEnabled.equalsIgnoreCase("false");
		}
		return false;
	}
}
