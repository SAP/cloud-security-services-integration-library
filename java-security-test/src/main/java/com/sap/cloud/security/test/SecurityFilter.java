/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

class SecurityFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request instanceof HttpServletRequest) {
			if (((HttpServletResponse) response).getStatus() < 400) {
				chain.doFilter(request, response);
			}
		} else {
			chain.doFilter(request, response);
		}
	}

	@Override
	public void destroy() {
	}
}
