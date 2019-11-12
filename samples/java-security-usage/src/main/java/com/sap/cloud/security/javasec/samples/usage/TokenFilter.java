package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(TokenFilter.class);
	private final TokenExtractor tokenExtractor;
	private final Validator<Token> tokenValidator;
	
	
	interface TokenExtractor {
		Token fromAuthorizationHeader(String authorizationHeader);
	}
	
	public TokenFilter() {
		tokenExtractor = (authorizationHeader) -> new TokenImpl(authorizationHeader);
		tokenValidator = CombiningValidator.builderFor(Environment.getInstance().getXsuaaServiceConfiguration()).build();
	}

	TokenFilter(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public void init(FilterConfig filterConfig) {
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)  {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = tokenExtractor.fromAuthorizationHeader(authorizationHeader);
					ValidationResult result = tokenValidator.validate(token);
					if (result.isValid()) {
						SecurityContext.setToken(token);
						filterChain.doFilter(request, response);
					} else {
						unauthorized(httpResponse, "Error during token validation: " + result.getErrorDescription());
					}
				} catch (Exception e) {
					unauthorized(httpResponse, "Unexpected error occured: " + e.getMessage());
				}
			} else {
				unauthorized(httpResponse, "Authorization header is missing");
			}
		}
	}

	private void unauthorized(HttpServletResponse httpResponse, String message) {
		logger.error(message);
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

	@Override
	public void destroy() {
		SecurityContext.clearToken();
	}

}
