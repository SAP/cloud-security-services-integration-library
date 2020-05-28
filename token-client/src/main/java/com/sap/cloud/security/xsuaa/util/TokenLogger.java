package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Logs the decoded jwt token.
 */
public class TokenLogger {

	private static final Logger INTERNAL_LOGGER = LoggerFactory.getLogger(TokenLogger.class);

	private final Logger wrappedLogger;
	private String convertedToken;

	/**
	 * Creates a new instance for the given {@coder logger}.
	 * @param logger the logger that is used to log the token
	 * @return a new instance
	 */
	public static TokenLogger getInstance(Logger logger) {
		return new TokenLogger(logger);
	}

	private TokenLogger(Logger logger) {
		Assertions.assertNotNull(logger, "Logger must be provided!");
		this.wrappedLogger = logger;
	}

	/**
	 * Decodes the given {@code token} string using {@link #convertToReadableFormat(String)}
	 * and logs the payload and header content on debug logging level with the provided logger.
	 * A description can be provided that will be logged alongside the token.
	 *
	 * @param token       the encoded jwt token string
	 * @param description an optional textual description of the token being logged
	 */
	public void logToken(String token, @Nullable String description) {
		if (!wrappedLogger.isDebugEnabled()) {
			return;
		}
		String convertedToken = convertToReadableFormat(token);
		if (convertedToken.isEmpty()) {
			return;
		}
		if (description != null) {
			wrappedLogger.debug(description);
		}
		wrappedLogger.debug(convertedToken);
	}

	/**
	 * Utility method to transform a encoded token to a human readable format
	 * while omitting the token signature. This can be used to inspect the token
	 * for debugging purposes.
	 * This method does not log the token! Use {@link #logToken(String, String)}
	 * for this.
	 * If the token is malformed or null, this method will return the empty string
	 * and not throw exceptions.
	 *
	 * @param token the jwt string
	 * @return readable format of the token
	 */
	public static String convertToReadableFormat(String token) {
		StringBuilder stringBuilder = new StringBuilder();
		try {
			DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(token);
			stringBuilder.append("Jwt header" + System.lineSeparator());
			stringBuilder.append("\t" + decodedJwt.getHeader());
			stringBuilder.append("Jwt payload" + System.lineSeparator());
			stringBuilder.append("\t" + decodedJwt.getPayload());
		} catch (Exception e) {
			INTERNAL_LOGGER.debug("Could not convert token to readable format:", e.getMessage());
			return "";
		}
		return stringBuilder.toString();
	}
}
