/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.x509.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread wide {@link Token} storage.
 */
public class SecurityContext {
	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

	private SecurityContext() {
	}

	private static final ThreadLocal<Token> tokenStorage = new ThreadLocal<>();
	private static final ThreadLocal<List<String>> servicePlanStorage = new ThreadLocal<List<String>>();
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
   * @param certificate certificate to be saved.
   */
  public static void setClientCertificate(final Certificate certificate) {
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
   * @param token token to be saved.
   */
  public static void setToken(final Token token) {
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
	 * Returns the Identity service broker plans that are stored in the thread local storage
	 *
	 * @return a list of Identity service broker plans
	 */
	public static List<String> getServicePlans() {
		return servicePlanStorage.get();
	}

  /**
   * Saves the Identity service broker plans in thread local storage.
   *
   * @param servicePlansHeader unprocessed Identity Service broker plan header value from response
   */
  public static void setServicePlans(final String servicePlansHeader) {
    // the header format contains a comma-separated list of quoted plan names, e.g. "plan1","plan
    // \"two\"","plan3"
    final String[] planParts =
        servicePlansHeader.trim().split("\\s*,\\s*"); // split by <whitespaces>,<whitespaces>

    // remove " around plan names
    final List<String> plans =
        Arrays.stream(planParts)
            .map(plan -> plan.substring(1, plan.length() - 1))
            .collect(Collectors.toList());

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Sets Identity Service Plan {} to SecurityContext (thread-locally).",
					plans);
		}

		servicePlanStorage.set(plans);
	}

	/**
	 * Clears the current Identity Service broker plans from thread wide storage.
	 */
	public static void clearServicePlans() {
		final List<String> plans = servicePlanStorage.get();
		if (plans != null && plans.size() != 0) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Service plans {} removed from SecurityContext (thread-locally).", plans);
			}
			servicePlanStorage.remove();
		}
	}



  /**
   * Clears the current token, certificate and Identity service broker plans from thread wide
   * storage.
   */
  public static void clear() {
    clearCertificate();
    clearToken();
    clearServicePlans();
	}

}