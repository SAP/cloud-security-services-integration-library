/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.x509.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread wide {@link Token} storage.
 */
public class SecurityContext {
	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

  private SecurityContext() {}

  private static final ThreadLocal<Token> tokenStorage = new ThreadLocal<>();
  private static final ThreadLocal<Token> idTokenStorage = new ThreadLocal<>();
  private static final ThreadLocal<Token> initialTokenStorage = new ThreadLocal<>();
  private static final ThreadLocal<List<String>> servicePlanStorage = new ThreadLocal<>();
  private static final ThreadLocal<Certificate> certificateStorage = new ThreadLocal<>();
  private static IdTokenExtension idTokenExtension;

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
    LOGGER.debug(
        "Sets token of service {} to SecurityContext (thread-locally).",
        token != null ? token.getService() : "null");
    tokenStorage.set(token);
    initialTokenStorage.set(token);
    idTokenStorage.remove();
  }

  /**
   * Saves the token thread wide. Only used in special cases to overwrite only the token for
   * internal usage.
   *
   * @param token token to be saved.
   */
  public static void overwriteToken(final Token token) {
    LOGGER.debug(
        "Sets token of service {} to SecurityContext (thread-locally).",
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

  @Nullable
  public static Token getInitialToken() {
    return initialTokenStorage.get();
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
   * Registers a custom {@link IdTokenExtension} to enhance the {@link SecurityContext} with
   * additional functionality.
   *
   * <p>The provided extension will be used by {@link #getIdToken()} and other context-aware methods
   * that rely on extended token handling logic.
   *
   * <p>Typical usage:
   *
   * <pre>
   * IdTokenExtension idTokenExt = new IdTokenExtension(tokenService, iasConfig);
   * SecurityContext.registerIdTokenExtension(idTokenExt);
   * </pre>
   *
   * @param ext the {@link IdTokenExtension} implementation to register, may be {@code null}
   */
  public static void registerIdTokenExtension(IdTokenExtension ext) {
    idTokenExtension = ext;
  }

  /**
   * Resolves an OpenID Connect ID token for the current user.
   *
   * <p>Checks if a token is already present in the thread local storage and if it is still valid
   * (not expired or about to expire within 5 minutes). If a valid token is found, it is returned.
   * If no valid token is found, it checks if an IdTokenExtension is registered.
   *
   * <p>If an extension is present, {@link IdTokenExtension#resolveIdToken()} will be invoked. If no
   * extension is registered, {@code null} is returned.
   *
   * <p><b>Example:</b>
   *
   * <pre>
   * SecurityContext.registerIdTokenExtension(new IdTokenExtension(tokenService, iasConfig));
   * String idToken = SecurityContext.getIdToken();
   * </pre>
   *
   * @return the ID token or {@code null} if no valid token is present and no extension is
   *     registered.
   */
  @Nullable
  public static Token getIdToken() {
    Token idToken = idTokenStorage.get();
    if (idToken != null) {
      if (Objects.nonNull(idToken.getExpiration())
          && idToken.getExpiration().minus(5, ChronoUnit.MINUTES).isAfter(Instant.now())) {
        return idToken;
      } else {
        idTokenStorage.remove();
      }
    }
    if (idTokenExtension != null) {
      idToken = idTokenExtension.resolveIdToken();
      idTokenStorage.set(idToken);
      return idToken;
    }
    return null;
  }

  private static void clear(ThreadLocal<Token> storage) {
    final Token token = storage.get();
    if (token != null) {
      LOGGER.debug(
          "Token of service {} removed from SecurityContext (thread-locally).", token.getService());
      storage.remove();
    }
  }

  /** Clears the current Token from thread wide storage. */
  public static void clearToken() {
    clear(tokenStorage);
  }

  /** Clears the current ID Token from thread wide storage. */
  public static void clearIdToken() {
    clear(idTokenStorage);
  }

  /** Clears the current ID Token from thread wide storage. */
  public static void clearInitialToken() {
    clear(initialTokenStorage);
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
    if (plans != null && !plans.isEmpty()) {
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
    clearIdToken();
    clearInitialToken();
    clearServicePlans();
  }
}