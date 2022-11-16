/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(HelloJavaServlet.ENDPOINT)
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
			StringBuilder message = new StringBuilder();
			message.append("You ('");
			message.append(token.getClaimAsString(TokenClaims.EMAIL));
			message.append("') can access the application with the following scopes: '");
			message.append(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES));
			message.append("'. ");
			// for authorization check you need the AccessToken interface (instead of Token)
			message.append("Having scope '$XSAPPNAME.Read'? " + token.hasLocalScope("Read"));
			response.getWriter().write(message.toString());
			response.setStatus(HttpServletResponse.SC_OK);
		} catch (final IOException e) {
			LOGGER.error("Failed to write error response: {}.", e.getMessage(), e);
		}
	}

}
