/**
 * Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/hello-java-security")
//@ServletSecurity(@HttpConstraint(rolesAllowed = { "read" })) // TODO WHAT needs to be done for AUTHZ checks?
public class HelloJavaServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(HelloJavaServlet.class);

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 * response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		response.setContentType("text/plain");
		Token token = SecurityContext.getToken();
		token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		try {
			response.getWriter().write("You ('"
					+ token.getClaimAsString(TokenClaims.XSUAA.EMAIL) + "') "
					+ "can access the application with the following scopes: '"
					+ token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES) + "'.");
			response.setStatus(HttpServletResponse.SC_OK);
		} catch (final IOException e) {
			logger.error("Failed to write error response: " + e.getMessage() + ".", e);
		}
	}

}
