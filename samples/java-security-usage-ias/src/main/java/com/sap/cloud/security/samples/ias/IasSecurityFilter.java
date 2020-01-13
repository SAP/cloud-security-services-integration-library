package com.sap.cloud.security.samples.ias;

import com.sap.cloud.security.servlet.IasTokenAuthenticator;
import com.sap.cloud.security.servlet.TokenAuthenticationResult;

import javax.servlet.*;
import java.io.IOException;

public class IasSecurityFilter implements Filter {

	private final IasTokenAuthenticator iasTokenAuthenticator;

	public IasSecurityFilter() {
		iasTokenAuthenticator = new IasTokenAuthenticator();
	}

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		TokenAuthenticationResult authenticationResult = iasTokenAuthenticator.validateRequest(request, response);
		if (authenticationResult.isAuthenticated()) {
			chain.doFilter(request, response) ;
		}
	}

	@Override
	public void destroy() {
	}
}
