/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples.ias;

import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.token.SecurityContext;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

@WebFilter("/*") // filter for any endpoint
public class IasSecurityFilter implements Filter {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasSecurityFilter.class);
	private final IasTokenAuthenticator iasTokenAuthenticator;

	public IasSecurityFilter() {
		iasTokenAuthenticator = new IasTokenAuthenticator();
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		if (httpRequest.getRequestURI().equals(HealthServlet.ENDPOINT)) {
			// Allow the request to proceed without any security check
			chain.doFilter(request, response);
		} else {
			try {
				TokenAuthenticationResult authenticationResult = iasTokenAuthenticator.validateRequest(request,
						response);
				if (authenticationResult.isAuthenticated()) {
					LOGGER.debug("AUTHENTICATED");
					chain.doFilter(request, response);
				} else {
					LOGGER.debug("UNAUTHENTICATED");
					sendUnauthenticatedResponse(response, authenticationResult.getUnauthenticatedReason());
				}
			} finally {
				SecurityContext.clear();
			}
		}
	}

	private void sendUnauthenticatedResponse(ServletResponse response, String unauthenticatedReason) {
		if (response instanceof HttpServletResponse httpServletResponse) {
			try {
				httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthenticatedReason); // 401
			} catch (IOException e) {
				LOGGER.error("Failed to send error response", e);
			}
		}
	}

}
