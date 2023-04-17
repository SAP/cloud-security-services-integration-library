/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenClaims;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class HelloJavaServlet extends HttpServlet {
	static final String ENDPOINT = "/hello-java-security";
	private static final Logger LOGGER = LoggerFactory.getLogger(HelloJavaServlet.class);

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		response.setContentType("text/plain");
		// same like SecurityContext.getToken() but more XSUAA specific methods
		AccessToken token = SecurityContext.getAccessToken();
		try {
			String message = "You ('" + token.getClaimAsString(TokenClaims.EMAIL) +
					"') can access the application with the following scopes: '" +
					token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES) + "'. " +
					// for authorization check you need the AccessToken interface (instead of Token)
					"Having scope '$XSAPPNAME.Read'? " + token.hasLocalScope("Read");
			response.getWriter().write(message);
			response.setStatus(HttpServletResponse.SC_OK);
		} catch (final IOException e) {
			LOGGER.error("Failed to write error response: {}.", e.getMessage(), e);
		}
	}

}
