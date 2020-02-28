package com.sap.cloud.security.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Thread wide {@link Token} storage.
 */
public class SecurityContext {
	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

	private SecurityContext() {
	}

	private static final ThreadLocal<Token> tokenStorage = new ThreadLocal<>();

	/**
	 * Saves the validated (!) token thread wide.
	 * 
	 * @param token
	 *            token to be saved.
	 */
	public static void setToken(Token token) {
		LOGGER.info("Sets token of service {} to SecurityContext (thread-locally).",
				token != null ? token.getService() : "null");
		tokenStorage.set(token);
	}

	/**
	 * Returns the token that is saved in thread wide storage.
	 * 
	 * 
	 * @return the token or null if the storage is empty.
	 */
	@Nullable
	public static Token getToken() {
		return tokenStorage.get();
	}

	/**
	 * Returns the token that is saved in thread wide storage.
	 *
	 *
	 * @return the token or null if the storage is empty or the token does not
	 *         implement the {@code AccessToken} interface.
	 */
	@Nullable
	public static AccessToken getAccessToken() {
		return tokenStorage.get() instanceof AccessToken ? (AccessToken) tokenStorage.get() : null;
	}

	/**
	 * Clears the current Token from thread wide storage.
	 */
	public static void clearToken() {
		final Token token = tokenStorage.get();
		LOGGER.debug("Token of service {} removed from SecurityContext (thread-locally).",
				token != null ? token.getService() : "null");
		tokenStorage.remove();
	}

}
