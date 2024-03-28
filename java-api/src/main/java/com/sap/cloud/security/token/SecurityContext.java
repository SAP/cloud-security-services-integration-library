/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Arrays;

/**
 * Thread wide {@link Token} storage.
 */
public class SecurityContext {
	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

	private SecurityContext() {
	}

	private static final ThreadLocal<Token> tokenStorage = new ThreadLocal<>();
	private static final ThreadLocal<String[]> planStorage = new ThreadLocal<>();
	private static final ThreadLocal<Certificate> certificateStorage = new ThreadLocal<>();

	/**
	 * Returns the certificate that is saved in thread wide storage.
	 *
	 * @return the certificate or null if the storage is empty.
	 */
	@Nullable
	public static Certificate getClientCertificate() {
		return certificateStorage.get();
	}

	/**
	 * Saves the certificate thread wide.
	 *
	 * @param certificate
	 * 		certificate to be saved.
	 */
	public static void setClientCertificate(Certificate certificate) {
		LOGGER.debug("Sets certificate to SecurityContext (thread-locally). {}",
				certificate);
		certificateStorage.set(certificate);
	}

	/**
	 * Clears the current Certificate from thread wide storage.
	 */
	private static void clearCertificate() {
		final Certificate certificate = certificateStorage.get();
		if (certificate != null) {
			LOGGER.debug("Certificate removed from SecurityContext (thread-locally).");
			certificateStorage.remove();
		}
	}

	/**
	 * Saves the validated (!) token thread wide.
	 *
	 * @param token
	 * 		token to be saved.
	 */
	public static void setToken(Token token) {
		LOGGER.debug("Sets token of service {} to SecurityContext (thread-locally).",
				token != null ? token.getService() : "null");
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
	 * Returns the token that is saved in thread wide storage.
	 *
	 * @return the token or null if the storage is empty or the token does not implement the {@code AccessToken}
	 * 		interface.
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
		if (token != null) {
			LOGGER.debug("Token of service {} removed from SecurityContext (thread-locally).", token.getService());
			tokenStorage.remove();
		}
	}

	/**
	 * Returns an Identity service broker plan that's been stored in thread local storage
	 *
	 * @return an array of Identity service broker plans
	 */
	public static String[] getServicePlan() {
		return planStorage.get();
	}

	/**
	 * Saves the Identity service broker plan name in thread local storage
	 *
	 * @param plan
	 * 		Identity service broker plan name
	 */
	public static void setServicePlan(String... plan) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Sets Identity Service Plan {} to SecurityContext (thread-locally).",
					Arrays.toString(plan));
		}
		planStorage.set(plan);
	}

	/**
	 * Clears the current Identity Broker Service Plan from thread wide storage.
	 */
	public static void clearServicePlan() {
		final String[] plan = planStorage.get();
		if (plan != null && plan.length != 0) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Service plan {} removed from SecurityContext (thread-locally).", Arrays.toString(plan));
			}
			planStorage.remove();
		}
	}

	/**
	 * Clears the current token and certificate from thread wide storage.
	 */
	public static void clear() {
		clearCertificate();
		clearToken();
		clearServicePlan();
	}

}
