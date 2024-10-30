/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xssec.samples.tokenflow.usage;

import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet("/hello-token-client")
public class HelloTokenClientServlet extends HttpServlet {

	private static XsuaaTokenFlows tokenFlows;

	@Override
	public void init() throws ServletException {
		OAuth2ServiceConfiguration configuration = Environments.getCurrent().getXsuaaConfiguration();

		try {
			tokenFlows = new XsuaaTokenFlows(
					new DefaultOAuth2TokenService(HttpClientFactory.create(configuration.getClientIdentity())),
					new XsuaaDefaultEndpoints(configuration), configuration.getClientIdentity());
		} catch (HttpClientException e) {
			throw new ServletException("Couldn't setup XsuaaTokenFlows");
		}
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setContentType("text/plain");

		OAuth2TokenResponse tokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();

		writeLine(response, "Access-Token: " + tokenResponse.getAccessToken());
		writeLine(response, "Access-Token-Payload: " + tokenResponse.getDecodedAccessToken().getPayload());
		writeLine(response, "Expired-At: " + tokenResponse.getExpiredAt());

	}

	private void writeLine(HttpServletResponse response, String string) throws IOException {
		response.getWriter().append(string);
		response.getWriter().append("\n");
	}

}
