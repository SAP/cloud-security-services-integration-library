/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License, 
 * v. 2 except as noted otherwise in the LICENSE file 
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xssec.samples.sapbuildpack;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;

/**
 * Servlet implementation class HelloTokenServlet
 */
@WebServlet("/hello-token")

// configure servlet to check against scope "$XSAPPNAME.Display"
@ServletSecurity(@HttpConstraint(rolesAllowed = { "Display" }))
public class HelloTokenServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("text/plain");
		XSUserInfo userInfo = (XSUserInfo) request.getUserPrincipal();

		try {
			response.getWriter().append("Client ID: ").append("" + userInfo.getClientId());
		response.getWriter().append("\n");
			response.getWriter().append("Email: ").append("" + userInfo.getEmail());
		response.getWriter().append("\n");
			response.getWriter().append("Family Name: ").append("" + userInfo.getFamilyName());
		response.getWriter().append("\n");
			response.getWriter().append("First Name: ").append("" + userInfo.getGivenName());
		response.getWriter().append("\n");
			response.getWriter().append("OAuth Grant Type: ").append("" + userInfo.getGrantType());
		response.getWriter().append("\n");
			response.getWriter().append("OAuth Token: ").append("" + userInfo.getAppToken());
		response.getWriter().append("\n");

		} catch (XSUserInfoException e) {
			e.printStackTrace(response.getWriter());
		}

	}

}
