/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xssec.samples.tokenflow.usage;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
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
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;

/**
 * Sample servlet demonstrating backward compatibility with Apache HttpClient 4.
 *
 * <p><strong>DEPRECATION NOTICE:</strong> This sample uses deprecated Apache HttpClient 4 constructors
 * for backward compatibility demonstration. These constructors will be removed in version 5.0.0.
 *
 * <p>For production applications, consider migrating to one of the following approaches:
 * <ul>
 *   <li><strong>Recommended:</strong> Use default Java 11 HttpClient (no custom HTTP client needed)</li>
 *   <li>Implement {@code HttpRequestExecutor} interface for custom HTTP client needs</li>
 * </ul>
 *
 * <p>See <a href="https://github.com/SAP/cloud-security-xsuaa-integration/blob/main/token-client/APACHE_HTTPCLIENT_MIGRATION.md">
 * Apache HttpClient Migration Guide</a> for detailed migration instructions.
 */
@WebServlet("/hello-token-client")
public class HelloTokenClientServlet extends HttpServlet {

	private static XsuaaTokenFlows tokenFlows;
	private static CloseableHttpClient httpClient;

	@Override
	public void init() throws ServletException {
		final OAuth2ServiceConfiguration configuration =
				Environments.getCurrent().getXsuaaConfiguration();
		DefaultTokenClientConfiguration.getInstance().setRetryEnabled(true);

		/*
		 * To change the default retry behavior, you can use the following code snippet:
		 * DefaultTokenClientConfiguration configuration = DefaultTokenClientConfiguration.getInstance();
		 * configuration.setRetryEnabled(true);
		 * configuration.setMaxRetryAttempts(5);
		 * configuration.setRetryDelayTime(2000); // in milliseconds
		 * configuration.setRetryStatusCodes(500, 502, 503, 504);
		 * OR as an alternative String representation:
		 * configuration.setRetryStatusCodes("500,502,503,504");
		 */

		// ========================================
		// BACKWARD COMPATIBILITY WITH APACHE HTTPCLIENT 4
		// ========================================
		// This demonstrates the deprecated approach using Apache HttpClient 4.
		// The constructor DefaultOAuth2TokenService(CloseableHttpClient) is deprecated
		// and will be removed in version 5.0.0.
		//
		// MIGRATION OPTIONS:
		//
		// Option 1 (Recommended): Use default Java 11 HttpClient - no custom client needed
		//   tokenFlows = new XsuaaTokenFlows(
		//       new DefaultOAuth2TokenService(), // Uses Java 11 HttpClient internally
		//       new XsuaaDefaultEndpoints(configuration),
		//       configuration.getClientIdentity()
		//   );
		//
		// Option 2: Custom HttpRequestExecutor for advanced configuration
		//   See: token-client/APACHE_HTTPCLIENT_MIGRATION.md

		// Configure Apache HttpClient 4 with custom settings
		httpClient = HttpClients.custom()
				.setMaxConnTotal(100)           // Max total connections
				.setMaxConnPerRoute(20)         // Max connections per route
				.build();

		// Use the DEPRECATED constructor - shows backward compatibility
		// This will generate deprecation warnings during compilation
		@SuppressWarnings("deprecation")
		DefaultOAuth2TokenService tokenService = new DefaultOAuth2TokenService(httpClient);

		tokenFlows = new XsuaaTokenFlows(
				tokenService,
				new XsuaaDefaultEndpoints(configuration),
				configuration.getClientIdentity());
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
			throws IOException {
		response.setContentType("text/plain");

		final OAuth2TokenResponse tokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();

		writeLine(response, "Access-Token: " + tokenResponse.getAccessToken());
		writeLine(response, "Access-Token-Payload: " + tokenResponse.getDecodedAccessToken().getPayload());
		writeLine(response, "Expired-At: " + tokenResponse.getExpiredAt());
	}

	@Override
	public void destroy() {
		// Clean up HTTP client resources
		if (httpClient != null) {
			try {
				httpClient.close();
			} catch (IOException e) {
				// Log error but don't throw from destroy
				System.err.println("Error closing HTTP client: " + e.getMessage());
			}
		}
	}

	private void writeLine(final HttpServletResponse response, final String string)
			throws IOException {
		response.getWriter().append(string);
		response.getWriter().append("\n");
	}

}
