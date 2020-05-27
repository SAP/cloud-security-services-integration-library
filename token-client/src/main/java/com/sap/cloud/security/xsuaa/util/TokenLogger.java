package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Logs the decoded jwt token.
 */
public class TokenLogger {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenLogger.class);

	/**
	 * Decodes the given {@code token} string and logs the payload and header
	 * content on debug logging level. A description can be provided that will be logged alongside the token.
	 *
	 * @param token the encoded jwt token string.
	 * @param description description that is log along the token content.
	 */
	public static void logToken(String token, @Nullable String description) {
		if (!LOGGER.isDebugEnabled()) {
			return;
		}
		if (token == null || token.isEmpty()) {
			LOGGER.debug("Could not log token string that is null or empty");
			return;
		}
		try {
			DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(token);
			if (description != null) {
				LOGGER.debug(description);
			}
			LOGGER.debug("Jwt token header" );
			LOGGER.debug("  " + decodedJwt.getHeader());
			LOGGER.debug("Jwt token payload");
			LOGGER.debug("  " + decodedJwt.getPayload());
		} catch (Exception e) {
			LOGGER.debug("Could not decode jwt token for logging purposes: ", e.getMessage());
		}
	}
}
