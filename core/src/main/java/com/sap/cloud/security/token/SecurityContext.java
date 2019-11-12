package com.sap.cloud.security.token;

import javax.annotation.Nullable;

/**
 * Thread wide {@link Token} storage.
 */
public class SecurityContext {

	private SecurityContext() {
	}

	private static final ThreadLocal<Token> tokenStorage = new ThreadLocal<>();

	/**
	 * Saves the given token thread wide.
	 * 
	 * @param token
	 *            token to be saved.
	 */
	public static void setToken(Token token) {
		tokenStorage.set(token);
	}

	/**
	 * Returns the token that is saved in thread wide storage.
	 * 
	 * @return the token or null if the storage is empty.
	 */
	@Nullable
	public static Token getToken() {
		return tokenStorage.get();
	}

	/**
	 * Clears the current Token from thread wide storage.
	 */
	public static void clearToken() {
		tokenStorage.remove();
	}

}
