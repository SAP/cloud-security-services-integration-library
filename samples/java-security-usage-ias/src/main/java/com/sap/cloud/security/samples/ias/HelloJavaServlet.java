/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples.ias;

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

@WebServlet(HelloJavaServlet.ENDPOINT)
public class HelloJavaServlet extends HttpServlet {
	static final String ENDPOINT = "/hello-java-security-ias";
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(HelloJavaServlet.class);

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		response.setContentType("text/plain");
		Token token = SecurityContext.getToken();
		try {
			response.getWriter().write("You ('"
					+ token.getClaimAsString(TokenClaims.EMAIL) + "') "
					+ "are authenticated and can access the application.");
		} catch (final IOException e) {
			logger.error("Failed to write error response: " + e.getMessage() + ".", e);
		}
	}

}
