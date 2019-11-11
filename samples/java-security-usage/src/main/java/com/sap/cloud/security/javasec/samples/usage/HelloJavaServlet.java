/**
 * Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.javasec.samples.usage;


import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;

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

		/** BEGIN Servlet Filter **/
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
			Token token = new TokenImpl(authorizationHeader);

			CombiningValidator combiningValidator =
					CombiningValidator.builderFor(Environment.getInstance()
							.getXsuaaServiceConfiguration()) // NEEDS VCAP_SERVICES env
							.build();
			ValidationResult result = combiningValidator.validate(token);
			if(result.isValid()) {
				SecurityContext.setToken(token);
				logger.info(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES).toString());
				try {
					response.getWriter().write("You ('"
							+ token.getClaimAsString(TokenClaims.XSUAA.EMAIL)+ "') "
							+ "can access the application with the following scopes: '"
							+ token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)+ "'.");
					response.setStatus(HttpServletResponse.SC_OK);
					return;
				}
				catch( final IOException e ) {
					logger.error("Failed to write error response: " + e.getMessage() + ".", e);
				}
			} else {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				logger.error(result.getErrorDescription());
			}
		}
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		logger.error("access forbidden");

		/** END Servlet Filter **/

		SecurityContext.getToken().getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
	}

}
