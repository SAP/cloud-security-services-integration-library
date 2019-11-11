package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(TokenFilter.class);

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain filterChain) {

		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

			if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
				Token token = new TokenImpl(authorizationHeader);

				CombiningValidator<Token> combiningValidator =
						CombiningValidator.builderFor(Environment.getInstance()
								.getXsuaaServiceConfiguration()) // NEEDS VCAP_SERVICES env
								.build();
				ValidationResult result = combiningValidator.validate(token);
				if (result.isValid()) {
					SecurityContext.setToken(token);
					logger.info(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES).toString());
				} else {
					httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					logger.error(result.getErrorDescription());
				}
			}
			httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			logger.error("access forbidden");
		}
	}

	@Override
	public void destroy() {
	}

}
