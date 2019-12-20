package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TokenAuthenticator is used to authenticate a user sending servlet requests to
 * a service via token. It produces a {@link TokenAuthenticationResult}. The
 * result contains the necessary information to perform container specific
 * authentication. See the
 * [JettyTokenAuthenticator](src/main/java/com/sap/cloud/security/test/jetty/JettyTokenAuthenticator.java)
 * on how this is used with jetty to perform authentication.
 */
public interface TokenAuthenticator {

	/**
	 * Performs the authentication for the given request.
	 * 
	 * @param request
	 *            servlet request.
	 * @param response
	 *            servlet response.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response);

	/**
	 * Returns the {@link TokenExtractor} used to extract the token from the
	 * authorization header.
	 * 
	 * @return the {@link TokenExtractor} instance.
	 */
	TokenExtractor getTokenExtractor();

	interface TokenExtractor {
		Token from(String authorizationHeader);
	}
}
