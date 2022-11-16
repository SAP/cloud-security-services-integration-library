/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples;

import com.sap.cloud.security.token.SecurityContext;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(HelloJavaServletScopeProtected.ENDPOINT)
public class HelloJavaServletScopeProtected extends HttpServlet {
	static final String ENDPOINT = "/hello-java-security-authz";

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if(!SecurityContext.getAccessToken().hasLocalScope("Read")) {
			XsuaaSecurityFilter.sendUnauthorizedResponse(response, "Read");
		}
		response.setContentType("text/plain");
		response.getWriter().write("Read-protected method called!");
		response.setStatus(HttpServletResponse.SC_OK);
	}

}
